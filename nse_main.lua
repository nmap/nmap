-- Arguments when this file (function) is called, accessible via ...
--   [1] The NSE C library. This is saved in the local variable cnse for
--       access throughout the file.
--   [2] The list of categories/files/directories passed via --script.
-- The actual arguments passed to the anonymous main function:
--   [1] The list of hosts we run against.
--
-- When making changes to this code, please ensure you do not add any
-- code relying global indexing. Instead, create a local below for the
-- global you need access to. This protects the engine from possible
-- replacements made to the global environment, speeds up access, and
-- documents dependencies.
--
-- A few notes about the safety of the engine, that is, the ability for
-- a script developer to crash or otherwise stall NSE. The purpose of noting
-- these attack vectors is more to show the difficulty in accidently
-- breaking the system than to indicate a user may wish to break the
-- system through these means.
--  - A script writer can use the undocumented Lua function newproxy
--    to inject __gc code that could run (and error) at any location.
--  - A script writer can use the debug library to break out of
--    the "sandbox" we give it. This is made a little more difficult by
--    our use of locals to all Lua functions we use and the exclusion
--    of the main thread and subsequent user threads.
--  - A simple while true do end loop can stall the system. This can be
--    avoided by debug hooks to yield the thread at periodic intervals
--    (and perhaps kill the thread) but a C function like string.find and
--    a malicious pattern can stall the system from C just as easily.
--  - The garbage collector function is available to users and they may
--    cause the system to stall through improper use.
--  - Of course the os and io library can cause the system to also break.

local NAME = "NSE";

-- Script Scan phases.
local NSE_PRE_SCAN  = "NSE_PRE_SCAN";
local NSE_SCAN      = "NSE_SCAN";
local NSE_POST_SCAN = "NSE_POST_SCAN";

-- String keys into the registry (_R), for data shared with nse_main.cc.
local YIELD = "NSE_YIELD";
local BASE = "NSE_BASE";
local WAITING_TO_RUNNING = "NSE_WAITING_TO_RUNNING";
local DESTRUCTOR = "NSE_DESTRUCTOR";
local SELECTED_BY_NAME = "NSE_SELECTED_BY_NAME";

-- This is a limit on the number of script instance threads running at once. It
-- exists only to limit memory use when there are many open ports. It doesn't
-- count worker threads started by scripts.
local CONCURRENCY_LIMIT = 1000;

-- Table of different supported rules.
local NSE_SCRIPT_RULES = {
  prerule = "prerule",
  hostrule = "hostrule",
  portrule = "portrule",
  postrule = "postrule",
};

local _G = _G;

local assert = assert;
local collectgarbage = collectgarbage;
local error = error;
local ipairs = ipairs;
local loadfile = loadfile;
local loadstring = loadstring;
local next = next;
local pairs = pairs;
local rawget = rawget;
local rawset = rawset;
local select = select;
local setfenv = setfenv;
local setmetatable = setmetatable;
local tonumber = tonumber;
local tostring = tostring;
local type = type;
local unpack = unpack;

local coroutine = require "coroutine";
local create = coroutine.create;
local resume = coroutine.resume;
local status = coroutine.status;
local yield = coroutine.yield;
local wrap = coroutine.wrap;

local debug = require "debug";
local traceback = debug.traceback;
local _R = debug.getregistry();

local io = require "io";
local open = io.open;

local math = require "math";
local max = math.max;

local string = require "string";
local byte = string.byte;
local find = string.find;
local format = string.format;
local gsub = string.gsub;
local lower = string.lower;
local match = string.match;
local sub = string.sub;

local table = require "table";
local concat = table.concat;
local insert = table.insert;
local remove = table.remove;
local sort = table.sort;

local nmap = require "nmap";

local cnse, rules = ...; -- The NSE C library and Script Rules

do -- Append the nselib directory to the Lua search path
  local t, path = assert(cnse.fetchfile_absolute("nselib/"));
  assert(t == "directory", "could not locate nselib directory!");
  package.path = path.."?.lua;"..package.path;
end

local script_database_type, script_database_path =
    cnse.fetchfile_absolute(cnse.script_dbpath);
local script_database_update = cnse.scriptupdatedb;
local script_help = cnse.scripthelp;

local stdnse = require "stdnse";

(require "strict")() -- strict global checking

-- NSE_YIELD_VALUE
-- This is the table C uses to yield a thread with a unique value to
-- differentiate between yields initiated by NSE or regular coroutine yields.
local NSE_YIELD_VALUE = {};

do
  -- This is the method by which we allow a script to have nested
  -- coroutines. If a sub-thread yields in an NSE function such as
  -- nsock.connect, then we propogate the yield up. These replacements
  -- to the coroutine library are used only by Script Threads, not the engine.

  local function handle (co, status, ...)
    if status and NSE_YIELD_VALUE == ... then -- NSE has yielded the thread
      return handle(co, resume(co, yield(NSE_YIELD_VALUE)));
    else
      return status, ...;
    end
  end

  function coroutine.resume (co, ...)
    return handle(co, resume(co, ...));
  end

  local resume = coroutine.resume; -- local reference to new coroutine.resume
  local function aux_wrap (status, ...)
    if not status then
      return error(..., 2);
    else
      return ...;
    end
  end
  function coroutine.wrap (f)
    local co = create(f);
    return function (...)
      return aux_wrap(resume(co, ...));
    end
  end
end

-- Some local helper functions --

local log_write, verbosity, debugging =
    nmap.log_write, nmap.verbosity, nmap.debugging;
local log_write_raw = cnse.log_write;

local function print_verbose (level, fmt, ...)
  if verbosity() >= assert(tonumber(level)) or debugging() > 0 then
    log_write("stdout", format(fmt, ...));
  end
end

local function print_debug (level, fmt, ...)
  if debugging() >= assert(tonumber(level)) then
    log_write("stdout", format(fmt, ...));
  end
end

local function log_error (fmt, ...)
  log_write("stderr", format(fmt, ...));
end

local function table_size (t)
  local n = 0; for _ in pairs(t) do n = n + 1; end return n;
end

-- recursively copy a table, for host/port tables
-- not very rigorous, but it doesn't need to be
local function tcopy (t)
  local tc = {};
  for k,v in pairs(t) do
    if type(v) == "table" then
      tc[k] = tcopy(v);
    else
      tc[k] = v;
    end
  end
  return tc;
end

local Script = {}; -- The Script Class, its constructor is Script.new.
local Thread = {}; -- The Thread Class, its constructor is Script:new_thread.
do
  -- Thread:d()
  -- Outputs debug information at level 1 or higher.
  -- Changes "%THREAD" with an appropriate identifier for the debug level
  function Thread:d (fmt, ...)
    local against;
    if self.host and self.port then
      against = " against "..self.host.ip..":"..self.port.number;
    elseif self.host then
      against = " against "..self.host.ip;
    else
      against = "";
    end
    if debugging() > 1 then
      fmt = gsub(fmt, "%%THREAD_AGAINST", self.info..against);
      fmt = gsub(fmt, "%%THREAD", self.info);
    else
      fmt = gsub(fmt, "%%THREAD_AGAINST", self.short_basename..against);
      fmt = gsub(fmt, "%%THREAD", self.short_basename);
    end
    print_debug(1, fmt, ...);
  end

  -- Sets scripts output. Variable result is a string.
  function Thread:set_output(result)
    if self.type == "prerule" or self.type == "postrule" then
      cnse.script_set_output(self.id, result);
    elseif self.type == "hostrule" then
      cnse.host_set_output(self.host, self.id, result);
    elseif self.type == "portrule" then
      cnse.port_set_output(self.host, self.port, self.id, result);
    end
  end

  -- prerule/postrule scripts may be timed out in the future
  -- based on start time and script lifetime?
  function Thread:timed_out ()
    if self.type == "hostrule" or self.type == "portrule" then
      return cnse.timedOut(self.host);
    end
    return nil;
  end

  function Thread:start_time_out_clock ()
    if self.type == "hostrule" or self.type == "portrule" then
      cnse.startTimeOutClock(self.host);
    end
  end

  function Thread:stop_time_out_clock ()
    if self.type == "hostrule" or self.type == "portrule" then
      cnse.stopTimeOutClock(self.host);
    end
  end

  -- Register scripts in the timeouts list to track their timeouts.
  function Thread:start (timeouts)
    self:d("Starting %THREAD_AGAINST.");
    if self.host then
      timeouts[self.host] = timeouts[self.host] or {};
      timeouts[self.host][self.co] = true;
    end
  end

  -- Remove scripts from the timeouts list and call their
  -- destructor handles.
  function Thread:close (timeouts, result)
    self.error = result;
    if self.host then
      timeouts[self.host][self.co] = nil;
      -- Any more threads running for this script/host?
      if not next(timeouts[self.host]) then
        self:stop_time_out_clock();
        timeouts[self.host] = nil;
      end
    end
    local ch = self.close_handlers;
    for key, destructor_t in pairs(ch) do
      destructor_t.destructor(destructor_t.thread, key);
      ch[key] = nil;
    end
  end

  -- thread = Script:new_thread(rule, ...)
  -- Creates a new thread for the script Script.
  -- Arguments:
  --   rule  The rule argument the rule, hostrule or portrule, tested.
  --   ...   The arguments passed to the rule function (host[, port]).
  -- Returns:
  --   thread  The thread (class) is returned, or nil.
  function Script:new_thread (rule, ...)
    local script_type = assert(NSE_SCRIPT_RULES[rule]);
    if not self[rule] then return nil end -- No rule for this script?
    local file_closure = self.file_closure;
    -- Rebuild the environment for the running thread.
    local env = {
        SCRIPT_PATH = self.filename,
        SCRIPT_NAME = self.short_basename,
        SCRIPT_TYPE = script_type,
    };
    setmetatable(env, {__index = _G});
    setfenv(file_closure, env);
    local unique_value = {}; -- to test valid yield
    local function main (...)
      file_closure(); -- loads script globals
      return env.action(yield(unique_value, env[rule](...)));
    end
    setfenv(main, env);
    -- This thread allows us to load the script's globals in the
    -- same Lua thread the action and rule functions will execute in.
    local co = create(main);
    local s, value, rule_return = resume(co, ...);
    setfenv(file_closure, _G); -- reset the environment
    if s and value ~= unique_value then
      print_debug(1,
    "A thread for %s yielded unexpectedly in the file or %s function:\n%s\n",
          self.filename, rule, traceback(co));
    elseif s and rule_return then
      local thread = {
        co = co,
        env = env,
        identifier = tostring(co),
        info = format("'%s' (%s)", self.short_basename, tostring(co));
        type = script_type,
        close_handlers = {},
      };
      setmetatable(thread, {
        __metatable = Thread,
        __index = function (thread, k) return Thread[k] or self[k] end
      }); -- Access to the parent Script
      thread.parent = thread; -- itself
      return thread;
    elseif not s then
      print_debug(1, "a thread for %s failed to load:\n%s\n", self.filename,
          traceback(co, tostring(rule_return)));
    end
    return nil;
  end

  local required_fields = {
    description = "string",
    action = "function",
    categories = "table",
    dependencies = "table",
  };
  -- script = Script.new(filename)
  -- Creates a new Script Class for the script.
  -- Arguments:
  --   filename  The filename (path) of the script to load.
  -- Returns:
  --   script  The script (class) created.
  function Script.new (filename)
    assert(type(filename) == "string", "string expected");
    if not find(filename, "%.nse$") then
      log_error(
          "Warning: Loading '%s' -- the recommended file extension is '.nse'.",
          filename);
    end
    local basename = match(filename, "[/\\]([^/\\]-)$") or filename;
    local short_basename = match(filename, "[/\\]([^/\\]-)%.nse$") or
                       match(filename, "[/\\]([^/\\]-)%.[^.]*$") or
                       filename;
    local file_closure = assert(loadfile(filename));
    -- Give the closure its own environment, with global access
    local env = {
      SCRIPT_PATH = filename,
      SCRIPT_NAME = short_basename,
      dependencies = {},
    };
    setmetatable(env, {__index = _G});
    setfenv(file_closure, env);
    local co = create(file_closure); -- Create a garbage thread
    assert(resume(co)); -- Get the globals it loads in env
    -- Check that all the required fields were set
    for f, t in pairs(required_fields) do
      local field = rawget(env, f);
      if field == nil then
        error(filename.." is missing required field: '"..f.."'");
      elseif type(field) ~= t then
        error(filename.." field '"..f.."' is of improper type '"..
            type(field).."', expected type '"..t.."'");
      end
    end
    -- Check the required rule functions
    local rules = {}
    for rule in pairs(NSE_SCRIPT_RULES) do
      local rulef = rawget(env, rule);
      assert(type(rulef) == "function" or rulef == nil,
          rule.." must be a function!");
      rules[rule] = rulef;
    end
    assert(next(rules), filename.." is missing required function: 'rule'");
    local prerule = rules.prerule;
    local hostrule = rules.hostrule;
    local portrule = rules.portrule;
    local postrule = rules.postrule;
    -- Assert that categories is an array of strings
    for i, category in ipairs(rawget(env, "categories")) do
      assert(type(category) == "string", 
        filename.." has non-string entries in the 'categories' array");
    end
    -- Assert that dependencies is an array of strings
    for i, dependency in ipairs(rawget(env, "dependencies")) do
      assert(type(dependency) == "string", 
        filename.." has non-string entries in the 'dependencies' array");
    end
    -- Return the script
    local script = {
      filename = filename,
      basename = basename,
      short_basename = short_basename,
      id = match(filename, "^.-[/\\]([^\\/]-)%.nse$") or short_basename,
      file_closure = file_closure,
      prerule = prerule,
      hostrule = hostrule,
      portrule = portrule,
      postrule = postrule,
      args = {n = 0};
      description = rawget(env, "description"),
      categories = rawget(env, "categories"),
      author = rawget(env, "author"),
      license = rawget(env, "license"),
      dependencies = rawget(env, "dependencies"),
      threads = {},
      selected_by_name = false,
    };
    return setmetatable(script, {__index = Script, __metatable = Script});
  end
end

-- check_rules(rules)
-- Adds the "default" category if no rules were specified.
-- Adds other implicitly specified rules (e.g. "version")
--
-- Arguments:
--   rules  The array of rules to check.
local function check_rules (rules)
  if cnse.default and #rules == 0 then rules[1] = "default" end
  if cnse.scriptversion then rules[#rules+1] = "version" end
end

-- chosen_scripts = get_chosen_scripts(rules)
-- Loads all the scripts for the given rules using the Script Database.
-- Arguments:
--   rules  The array of rules to use for loading scripts.
-- Returns:
--   chosen_scripts  The array of scripts loaded for the given rules. 
local function get_chosen_scripts (rules)
  check_rules(rules);

  local db_closure = assert(loadfile(script_database_path),
    "database appears to be corrupt or out of date;\n"..
    "\tplease update using: nmap --script-updatedb");

  local chosen_scripts, entry_rules, used_rules, files_loaded = {}, {}, {}, {};

  -- Tokens that are allowed in script rules (--script)
  local protected_lua_tokens = {
    ["and"] = true,
    ["or"] = true,
    ["not"] = true,
  };
  -- Globalize all names in str that are not protected_lua_tokens
  local function globalize (str)
    local lstr = lower(str);
    if protected_lua_tokens[lstr] then
      return lstr;
    else
      return 'm("'..str..'")';
    end
  end

  for i, rule in ipairs(rules) do
    rule = match(rule, "^%s*(.-)%s*$"); -- strip surrounding whitespace
    used_rules[rule] = false; -- has not been used yet
    -- Globalize all `names`, all visible characters not ',', '(', ')', and ';'
    local globalized_rule =
        gsub(rule, "[\033-\039\042-\043\045-\058\060-\126]+", globalize);
    -- Precompile the globalized rule
    local compiled_rule, err = loadstring("return "..globalized_rule, "rule");
    if not compiled_rule then
      err = err:match("rule\"]:%d+:(.+)$"); -- remove (luaL_)where in code
      error("Bad script rule:\n\t"..rule.." -> "..err);
    end
    entry_rules[globalized_rule] = {
      original_rule = rule,
      compiled_rule = compiled_rule,
    };
  end

  -- Checks if a given script, script_entry, should be loaded. A script_entry
  -- should be in the form: { filename = "name.nse", categories = { ... } }
  local function entry (script_entry)
    local categories, filename = script_entry.categories, script_entry.filename;
    assert(type(categories) == "table" and type(filename) == "string",
        "script database appears corrupt, try `nmap --script-updatedb`");
    local escaped_basename = match(filename, "([^/\\]-)%.nse$") or
                             match(filename, "([^/\\]-)$");

    local r_categories = {all = true}; -- A reverse table of categories
    for i, category in ipairs(categories) do
      assert(type(category) == "string", "bad entry in script database");
      r_categories[lower(category)] = true; -- Lowercase the entry
    end

    -- Was this entry selected by name with the --script option? We record
    -- whether it was so that scripts so selected can get a verbosity boost.
    -- See nmap.verbosity.
    local selected_by_name = false;
    -- A matching function for each script rule.
    -- If the pattern directly matches a category (e.g. "all"), then
    -- we return true. Otherwise we test if it is a filename or if
    -- the script_entry.filename matches the pattern.
    local function m (pattern)
      -- Check categories
      if r_categories[lower(pattern)] then return true end
      -- Check filename with wildcards
      pattern = gsub(pattern, "%.nse$", ""); -- remove optional extension
      pattern = gsub(pattern, "[%^%$%(%)%%%.%[%]%+%-%?]", "%%%1"); -- esc magic
      pattern = gsub(pattern, "%*", ".*"); -- change to Lua wildcard
      pattern = "^"..pattern.."$"; -- anchor to beginning and end
      local found = not not find(escaped_basename, pattern);
      selected_by_name = selected_by_name or found;
      return found;
    end
    local env = {m = m};

    local script;
    for globalized_rule, rule_table in pairs(entry_rules) do
      if setfenv(rule_table.compiled_rule, env)() then -- run the compiled rule
        used_rules[rule_table.original_rule] = true;
        local t, path = cnse.fetchscript(filename);
        if t == "file" then
          if not files_loaded[path] then
            script = Script.new(path);
            chosen_scripts[#chosen_scripts+1] = script;
            files_loaded[path] = true;
            -- do not break so other rules can be marked as used
          end
        else
          log_error("Warning: Could not load '%s': %s", filename, path);
          break;
        end
      end
    end
    if script then
      script.selected_by_name = selected_by_name;
      if script.selected_by_name then
        print_debug(2, "Script %s was selected by name.", script.basename);
      end
    end
  end

  setfenv(db_closure, {Entry = entry});
  db_closure(); -- Load the scripts

  -- Now load any scripts listed by name rather than by category.
  for rule, loaded in pairs(used_rules) do
    if not loaded then -- attempt to load the file/directory
      local t, path = cnse.fetchscript(rule);
      if t == nil then -- perhaps omitted the extension?
        t, path = cnse.fetchscript(rule..".nse");
      end
      if t == nil then
        error("'"..rule.."' did not match a category, filename, or directory");
      elseif t == "file" and not files_loaded[path] then
        local script = Script.new(path);
        script.selected_by_name = true;
        chosen_scripts[#chosen_scripts+1] = script;
        print_debug(2, "Script %s was selected by name.", script.filename);
        files_loaded[path] = true;
      elseif t == "directory" then
        for f in cnse.dir(path) do
          local file = path .."/".. f
          if find(f, "%.nse$") and not files_loaded[file] then
            chosen_scripts[#chosen_scripts+1] = Script.new(file);
            files_loaded[file] = true;
          end
        end
      end
    end
  end

  -- calculate runlevels
  local name_script = {};
  for i, script in ipairs(chosen_scripts) do
    assert(name_script[script.short_basename] == nil);
    name_script[script.short_basename] = script;
  end
  local chain = {}; -- chain of script names
  local function calculate_runlevel (script)
    chain[#chain+1] = script.short_basename;
    if script.runlevel == false then -- circular dependency 
      error("circular dependency in chain `"..concat(chain, "->").."`");
    else
      script.runlevel = false; -- placeholder
    end
    local runlevel = 1;
    for i, dependency in ipairs(script.dependencies) do
      -- yes, use rawget in case we add strong dependencies again
      local s = rawget(name_script, dependency);
      if s then
        local r = tonumber(s.runlevel) or calculate_runlevel(s);
        runlevel = max(runlevel, r+1);
      end
    end
    chain[#chain] = nil;
    script.runlevel = runlevel;
    return runlevel;
  end
  for i, script in ipairs(chosen_scripts) do
    local _ = script.runlevel or calculate_runlevel(script);
  end

  return chosen_scripts;
end

-- run(threads)
-- The main loop function for NSE. It handles running all the script threads.
-- Arguments:
--   threads  An array of threads (a runlevel) to run.
--   scantype  A string that indicates the current script scan phase.
local function run (threads_iter, scantype, hosts)
  -- running scripts may be resumed at any time. waiting scripts are
  -- yielded until Nsock wakes them. After being awakened with
  -- nse_restore, waiting threads become pending and later are moved all
  -- at once back to running.
  local running, waiting, pending = {}, {}, {};
  local all = setmetatable({}, {__mode = "kv"}); -- base coroutine to Thread
  local current; -- The currently running Thread.
  local total = 0; -- Number of threads, for record keeping.
  local timeouts = {}; -- A list to save and to track scripts timeout.
  local num_threads = 0; -- Number of script instances currently running.

  -- Map of yielded threads to the base Thread
  local yielded_base = setmetatable({}, {__mode = "kv"});
  -- _R[YIELD] is called by nse_yield in nse_main.cc
  _R[YIELD] = function (co)
    yielded_base[co] = current; -- set base
    return NSE_YIELD_VALUE; -- return NSE_YIELD_VALUE
  end
  _R[BASE] = function ()
    return current.co;
  end
  -- _R[WAITING_TO_RUNNING] is called by nse_restore in nse_main.cc
  _R[WAITING_TO_RUNNING] = function (co, ...)
    local base = yielded_base[co] or all[co]; -- translate to base thread
    if base then
      co = base.co;
      if waiting[co] then -- ignore a thread not waiting
        pending[co], waiting[co] = waiting[co], nil;
        pending[co].args = {n = select("#", ...), ...};
      end
    end
  end
  -- _R[DESTRUCTOR] is called by nse_destructor in nse_main.cc
  _R[DESTRUCTOR] = function (what, co, key, destructor)
    local thread = yielded_base[co] or all[co] or current;
    if thread then
      local ch = thread.close_handlers;
      if what == "add" then
        ch[key] = {
          thread = co,
          destructor = destructor
        };
      elseif what == "remove" then
        ch[key] = nil;
      end
    end
  end
  _R[SELECTED_BY_NAME] = function()
    return current and current.selected_by_name;
  end
  rawset(stdnse, "new_thread", function (main, ...)
    assert(type(main) == "function", "function expected");
    local co = create(function(...) main(...) end); -- do not return results
    print_debug(2, "%s spawning new thread (%s).",
        current.parent.info, tostring(co));
    local thread = {
      co = co,
      id = current.id,
      args = {n = select("#", ...), ...},
      host = current.host,
      port = current.port,
      type = current.type,
      parent = current.parent,
      info = format("'%s' worker (%s)", current.short_basename, tostring(co));
      close_handlers = {},
      -- d = function(...) end, -- output no debug information
    };
    local thread_mt = {
      __metatable = Thread,
      __index = current,
    };
    setmetatable(thread, thread_mt);
    total, all[co], pending[co] = total+1, thread, thread;
    local function info ()
      return status(co), rawget(thread, "error");
    end
    return co, info;
  end);
  rawset(stdnse, "base", function ()
    return current.co;
  end);

  while threads_iter and num_threads < CONCURRENCY_LIMIT do
    local thread = threads_iter()
    if not thread then
      threads_iter = nil;
      break;
    end
    all[thread.co], running[thread.co], total = thread, thread, total+1;
    num_threads = num_threads + 1;
    thread:start(timeouts);
  end
  if num_threads == 0 then
    return
  end

  if (scantype == NSE_PRE_SCAN) then
    print_verbose(1, "Script Pre-scanning.");
  elseif (scantype == NSE_SCAN) then
    if #hosts > 1 then
      print_verbose(1, "Script scanning %d hosts.", #hosts);
    elseif #hosts == 1 then
      print_verbose(1, "Script scanning %s.", hosts[1].ip);
    end
  elseif (scantype == NSE_POST_SCAN) then
    print_verbose(1, "Script Post-scanning.");
  end

  local progress = cnse.scan_progress_meter(NAME);

  -- Loop while any thread is running or waiting.
  while next(running) or next(waiting) or threads_iter do
    -- Start as many new threads as possible.
    while threads_iter and num_threads < CONCURRENCY_LIMIT do
      local thread = threads_iter()
      if not thread then
        threads_iter = nil;
        break;
      end
      all[thread.co], running[thread.co], total = thread, thread, total+1;
      num_threads = num_threads + 1;
      thread:start(timeouts);
    end

    local nr, nw = table_size(running), table_size(waiting);
    if cnse.key_was_pressed() then
      print_verbose(1, "Active NSE Script Threads: %d (%d waiting)\n",
          nr+nw, nw);
      progress("printStats", 1-(nr+nw)/total);
      if debugging() >= 2 then
        for co, thread in pairs(running) do
          thread:d("Running: %THREAD\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
        for co, thread in pairs(waiting) do
          thread:d("Waiting: %THREAD\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
      end
    elseif progress "mayBePrinted" then
      if verbosity() > 1 or debugging() > 0 then
        progress("printStats", 1-(nr+nw)/total);
      else
        progress("printStatsIfNecessary", 1-(nr+nw)/total);
      end
    end

    -- Checked for timed-out scripts and hosts.
    for co, thread in pairs(waiting) do
      if thread:timed_out() then
        waiting[co], all[co], num_threads = nil, nil, num_threads-1;
        thread:d("%THREAD %stimed out", thread.host
            and format("%s%s ", thread.host.ip,
                    thread.port and ":"..thread.port.number or "")
            or "");
        thread:close(timeouts, "timed out");
      end
    end

    for co, thread in pairs(running) do
      current, running[co] = thread, nil;
      thread:start_time_out_clock();

      local s, result = resume(co, unpack(thread.args, 1, thread.args.n));
      if not s then -- script error...
        all[co], num_threads = nil, num_threads-1;
        thread:d("%THREAD_AGAINST threw an error!\n%s\n",
            traceback(co, tostring(result)));
        thread:close(timeouts, result);
      elseif status(co) == "suspended" then
        if result == NSE_YIELD_VALUE then
          waiting[co] = thread;
        else
          all[co], num_threads = nil, num_threads-1;
          thread:d("%THREAD yielded unexpectedly and cannot be resumed.");
          thread:close();
        end
      elseif status(co) == "dead" then
        all[co], num_threads = nil, num_threads-1;
        if type(result) == "string" then
          -- Escape any character outside the range 32-126 except for tab,
          -- carriage return, and line feed. This makes the string safe for
          -- screen display as well as XML (see section 2.2 of the XML spec).
          result = gsub(result, "[^\t\r\n\032-\126]", function(a)
            return format("\\x%02X", byte(a));
          end);
          thread:set_output(result);
        end
        thread:d("Finished %THREAD_AGAINST.");
        thread:close(timeouts);
      end
      current = nil;
    end

    cnse.nsock_loop(50); -- Allow nsock to perform any pending callbacks
    -- Move pending threads back to running.
    for co, thread in pairs(pending) do
      pending[co], running[co] = nil, thread;
    end

    collectgarbage "step";
  end

  progress "endTask";
end

-- Format NSEDoc markup (e.g., including bullet lists and <code> sections) into
-- a display string at the given indentation level. Currently this only indents
-- the string and doesn't interpret any other markup.
local function format_nsedoc(nsedoc, indent)
  indent = indent or ""

  return gsub(nsedoc, "([^\n]+)", indent .. "%1")
end

-- Return the NSEDoc URL for the script with the given id.
local function nsedoc_url(id)
  return format("%s/nsedoc/scripts/%s.html", cnse.NMAP_URL, id)
end

local function script_help_normal(chosen_scripts)
  for i, script in ipairs(chosen_scripts) do
    log_write_raw("stdout", "\n");
    log_write_raw("stdout", format("%s\n", script.id));
    log_write_raw("stdout", format("Categories: %s\n", concat(script.categories, " ")));
    log_write_raw("stdout", format("%s\n", nsedoc_url(script.id)));
    log_write_raw("stdout", format_nsedoc(script.description, "  "));
  end
end

local function script_help_xml(chosen_scripts)
  cnse.xml_start_tag("nse-scripts");
  cnse.xml_newline();

  local t, scripts_dir, nselib_dir
  t, scripts_dir = cnse.fetchfile_absolute("scripts/")
  assert(t == 'directory', 'could not locate scripts directory');
  t, nselib_dir = cnse.fetchfile_absolute("nselib/")
  assert(t == 'directory', 'could not locate nselib directory');
  cnse.xml_start_tag("directory", { name = "scripts", path = scripts_dir });
  cnse.xml_end_tag();
  cnse.xml_newline();
  cnse.xml_start_tag("directory", { name = "nselib", path = nselib_dir });
  cnse.xml_end_tag();
  cnse.xml_newline();

  for i, script in ipairs(chosen_scripts) do
    cnse.xml_start_tag("script", { filename = script.filename });
    cnse.xml_newline();

    cnse.xml_start_tag("categories");
    for _, category in ipairs(script.categories) do
      cnse.xml_start_tag("category");
      cnse.xml_write_escaped(category);
      cnse.xml_end_tag();
    end
    cnse.xml_end_tag();
    cnse.xml_newline();

    cnse.xml_start_tag("description");
    cnse.xml_write_escaped(script.description);
    cnse.xml_end_tag();
    cnse.xml_newline();

    -- script
    cnse.xml_end_tag();
    cnse.xml_newline();
  end

  -- nse-scripts
  cnse.xml_end_tag();
  cnse.xml_newline();
end

do -- Load script arguments (--script-args)
  local args = cnse.scriptargs or "";

  -- Parse a string in 'str' at 'start'.
  local function parse_string (str, start)
    -- Unquoted
    local uqi, uqj, uqm = find(str,
        "^%s*([^'\"%s{},=][^{},=]-)%s*[},=]", start);
    -- Quoted
    local qi, qj, q, qm = find(str, "^%s*(['\"])(.-[^\\])%1%s*[},=]", start);
    -- Empty Quote
    local eqi, eqj = find(str, "^%s*(['\"])%1%s*[},=]", start);
    if uqi then
      return uqm, uqj-1;
    elseif qi then
      return gsub(qm, "\\"..q, q), qj-1;
    elseif eqi then
      return "", eqj-1;
    else
      error("Value around '"..sub(str, start, start+10)..
          "' is invalid or is unterminated by a valid seperator");
    end
  end
  -- Takes 'str' at index 'start' and parses a table. 
  -- Returns the table and the place in the string it finished reading.
  local function parse_table (str, start)
    local _, j = find(str, "^%s*{", start);
    local t = {}; -- table we return
    local tmp, nc; -- temporary and next character inspected

    while true do
      j = j+1; -- move past last token

      _, j, nc = find(str, "^%s*(%S)", j);

      if nc == "}" then -- end of table
        return t, j;
      else -- try to read key/value pair, or array value
        local av = false; -- this is an array value?
        if nc == "{" then -- array value
          av, tmp, j = true, parse_table(str, j);
        else
          tmp, j = parse_string(str, j);
        end
        nc = sub(str, j+1, j+1); -- next token
        if not av and nc == "=" then -- key/value?
          _, j, nc = find(str, "^%s*(%S)", j+2);
          if nc == "{" then
            t[tmp], j = parse_table(str, j);
          else -- regular string
            t[tmp], j = parse_string(str, j);
          end
          nc = sub(str, j+1, j+1); -- next token
        else -- not key/value pair, save array value
          t[#t+1] = tmp;
        end
        if nc == "," then j = j+1 end -- skip "," token
      end
    end
  end
  nmap.registry.args = parse_table("{"..args.."}", 1);
end

-- Update Missing Script Database?
if script_database_type ~= "file" then
  print_verbose(1, "Script Database missing, will create new one.");
  script_database_update = true; -- force update
end

if script_database_update then
  log_write("stdout", "Updating rule database.");
  local t, path = cnse.fetchfile_absolute('scripts/'); -- fetch script directory
  assert(t == 'directory', 'could not locate scripts directory');
  script_database_path = path.."script.db";
  local db = assert(open(script_database_path, 'w'));
  local scripts = {};
  for f in cnse.dir(path) do
    if match(f, '%.nse$') then
      scripts[#scripts+1] = path.."/"..f;
    end
  end
  sort(scripts);
  for i, script in ipairs(scripts) do
    script = Script.new(script);
    sort(script.categories);
    db:write('Entry { filename = "', script.basename, '", ');
    db:write('categories = {');
    for j, category in ipairs(script.categories) do
      db:write(' "', lower(category), '",');
    end
    db:write(' } }\n');
  end
  db:close();
  log_write("stdout", "Script Database updated successfully.");
end

-- Load all user chosen scripts
local chosen_scripts = get_chosen_scripts(rules);
print_verbose(1, "Loaded %d scripts for scanning.", #chosen_scripts);
for i, script in ipairs(chosen_scripts) do
  print_debug(2, "Loaded '%s'.", script.filename);
end

if script_help then
  script_help_normal(chosen_scripts);
  script_help_xml(chosen_scripts);
end

-- main(hosts)
-- This is the main function we return to NSE (on the C side), nse_main.cc
-- gets this function by loading and executing nse_main.lua. This
-- function runs a script scan phase according to its arguments.
-- Arguments:
--   hosts  An array of hosts to scan.
--   scantype A string that indicates the current script scan phase.
--    Possible string values are:
--      "SCRIPT_PRE_SCAN"
--      "SCRIPT_SCAN"
--      "SCRIPT_POST_SCAN"
local function main (hosts, scantype)
  -- Used to set up the runlevels.
  local threads, runlevels = {}, {};

  -- Every script thread has a table that is used in the run function
  -- (the main loop of NSE).
  -- This is the list of the thread table key/value pairs:
  --  Key     Value
  --  type    A string that indicates the rule type of the script.
  --  co      A thread object to identify the coroutine.
  --  parent  A table that contains the parent thread table (it self).
  --  close_handlers
  --          A table that contains the thread destructor handlers.
  --  info    A string that contains the script name and the thread 
  --            debug information.
  --  args    A table that contains the arguments passed to scripts, 
  --            arguments can be host and port tables.
  --  env     A table that contains the global script environment:
  --            categories, description, author, license, nmap table,
  --            action function, rule functions, SCRIPT_PATH, 
  --            SCRIPT_NAME, SCRIPT_TYPE (pre|host|port|post rule).
  --  identifier
  --          A string to identify the thread address.
  --  host    A table that contains the target host information. This
  --          will be nil for Pre-scanning and Post-scanning scripts.
  --  port    A table that contains the target port information. This
  --          will be nil for Pre-scanning and Post-scanning scripts.

  local runlevels = {};
  for i, script in ipairs(chosen_scripts) do
    runlevels[script.runlevel] = runlevels[script.runlevel] or {};
    insert(runlevels[script.runlevel], script);
  end

  for runlevel, scripts in ipairs(runlevels) do
    -- This iterator is passed to the run function. It returns one new script
    -- thread on demand until exhausted.
    local function threads_iter ()
      -- activate prerule scripts
      if (scantype == NSE_PRE_SCAN) then
        for _, script in ipairs(scripts) do
           local thread = script:new_thread("prerule");
           if thread then
             thread.args = {n = 0};
             yield(thread);
           end
        end
      -- activate hostrule and portrule scripts
      elseif (scantype == NSE_SCAN) then
        -- Check hostrules for this host.
        for j, host in ipairs(hosts) do
          for _, script in ipairs(scripts) do
            local thread = script:new_thread("hostrule", tcopy(host));
            if thread then
              thread.args, thread.host = {n = 1, tcopy(host)}, host;
              yield(thread);
            end
          end
          -- Check portrules for this host.
          for port in cnse.ports(host) do
            for _, script in ipairs(scripts) do
              local thread = script:new_thread("portrule", tcopy(host), tcopy(port));
              if thread then
                thread.args, thread.host, thread.port = {n = 2, tcopy(host), tcopy(port)}, host, port;
                yield(thread);
              end
            end
          end
        end
        -- activate postrule scripts
      elseif (scantype == NSE_POST_SCAN) then
        for _, script in ipairs(scripts) do
          local thread = script:new_thread("postrule");
          if thread then
            thread.args = {n = 0};
            yield(thread);
          end
        end
      end
    end
    print_verbose(2, "Starting runlevel %u (of %u) scan.", runlevel, #runlevels);
    run(wrap(threads_iter), scantype, hosts)
  end

  collectgarbage "collect";
end

return main;
