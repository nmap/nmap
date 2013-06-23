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

local _VERSION = _VERSION;
local MAJOR, MINOR = assert(_VERSION:match "^Lua (%d+).(%d+)$");
if tonumber(MAJOR.."."..MINOR) < 5.2 then
  error "NSE requires Lua 5.2 or newer. It looks like you're using an older version of nmap."
end

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
local FORMAT_TABLE = "NSE_FORMAT_TABLE";
local FORMAT_XML = "NSE_FORMAT_XML";

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

local cnse, rules = ...; -- The NSE C library and Script Rules

local _G = _G;

local assert = assert;
local collectgarbage = collectgarbage;
local error = error;
local ipairs = ipairs;
local load = load;
local loadfile = loadfile;
local next = next;
local pairs = pairs;
local pcall = pcall;
local rawget = rawget;
local rawset = rawset;
local require = require;
local select = select;
local setmetatable = setmetatable;
local tonumber = tonumber;
local tostring = tostring;
local type = type;

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
local lines = io.lines;
local open = io.open;

local math = require "math";
local max = math.max;

local package = require "package";

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
local unpack = table.unpack;

do -- Add loader to look in nselib/?.lua (nselib/ can be in multiple places)
  local function loader (lib)
    lib = lib:gsub("%.", "/"); -- change Lua "module seperator" to directory separator
    local name = "nselib/"..lib..".lua";
    local type, path = cnse.fetchfile_absolute(name);
    if type == "file" then
      return loadfile(path);
    else
      return "\n\tNSE failed to find "..name.." in search paths.";
    end
  end
  insert(package.searchers, 1, loader);
end

local nmap = require "nmap";
local lfs = require "lfs";

local socket = require "nmap.socket";
local loop = socket.loop;

local stdnse = require "stdnse";

local strict = require "strict";
assert(_ENV == _G);
strict(_ENV);

local script_database_type, script_database_path =
    cnse.fetchfile_absolute(cnse.script_dbpath);
local script_database_update = cnse.scriptupdatedb;
local script_help = cnse.scripthelp;

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

local function loadscript (filename)
  local source = "@"..filename;
  local function ld ()
    -- header for scripts to allow setting the environment
    yield [[return function (_ENV) return function (...)]];
    -- actual script
    for line in lines(filename, 2^15) do
      yield(line);
    end
    -- footer...
    yield [[ end end]];
    return nil;
  end
  return assert(load(wrap(ld), source, "t"))();
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

-- copies the host table while preserving the registry
local function host_copy(t)
  local h = tcopy(t)
  h.registry = t.registry
  return h
end

local REQUIRE_ERROR = {};
rawset(stdnse, "silent_require", function (...)
  local status, mod = pcall(require, ...);
  if not status then
    print_debug(1, "%s", traceback(mod));
    error(REQUIRE_ERROR)
  else
    return mod;
  end
end);

-- Gets a string containing as much of a host's name, IP, and port as are
-- available.
local function against_name(host, port)
  local targetname, ip, portno, ipport, against;
  if host then
    targetname = host.targetname;
    ip = host.ip;
  end
  if port then
    portno = port.number;
  end
  if ip and portno then
    ipport = ip..":"..portno;
  elseif ip then
    ipport = ip;
  end
  if targetname and ipport then
    against = targetname.." ("..ipport..")";
  elseif targetname then
    against = targetname;
  elseif ipport then
    against = ipport;
  end
  if against then
    return " against "..against
  else
    return ""
  end
end

-- The Script Class, its constructor is Script.new.
local Script = {};
-- The Thread Class, its constructor is Script:new_thread.
local Thread = {};
-- The Worker Class, it's a subclass of Thread. Its constructor is
-- Thread:new_worker. It (currently) has no methods.
local Worker = {};
do
  -- Workers reference data from parent thread.
  function Worker:__index (key)
    return Worker[key] or self.parent[key]
  end

  -- Thread:d()
  -- Outputs debug information at level 1 or higher.
  -- Changes "%THREAD" with an appropriate identifier for the debug level
  function Thread:d (fmt, ...)
    local against = against_name(self.host, self.port);
    if debugging() > 1 then
      fmt = gsub(fmt, "%%THREAD_AGAINST", self.info..against);
      fmt = gsub(fmt, "%%THREAD", self.info);
    else
      fmt = gsub(fmt, "%%THREAD_AGAINST", self.short_basename..against);
      fmt = gsub(fmt, "%%THREAD", self.short_basename);
    end
    print_debug(1, fmt, ...);
  end

  -- Sets script output. r1 and r2 are the (as many as two) return values.
  function Thread:set_output(r1, r2)
    if not self.worker then
      -- Structure table and unstructured string outputs.
      local tab, str
  
      if r2 then
        tab, str = r1, tostring(r2);
      elseif type(r1) == "string" then
        tab, str = nil, r1;
      elseif r1 == nil then
        return
      else
        tab, str = r1, nil;
      end
  
      if self.type == "prerule" or self.type == "postrule" then
        cnse.script_set_output(self.id, tab, str);
      elseif self.type == "hostrule" then
        cnse.host_set_output(self.host, self.id, tab, str);
      elseif self.type == "portrule" then
        cnse.port_set_output(self.host, self.port, self.id, tab, str);
      end
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
    local script_closure_generator = self.script_closure_generator;
    -- Rebuild the environment for the running thread.
    local env = {
        SCRIPT_PATH = self.filename,
        SCRIPT_NAME = self.short_basename,
        SCRIPT_TYPE = script_type,
    };
    setmetatable(env, {__index = _G});
    local script_closure = script_closure_generator(env);
    local unique_value = {}; -- to test valid yield
    local function main (_ENV, ...)
      script_closure(); -- loads script globals
      return action(yield(unique_value, _ENV[rule](...)));
    end
    -- This thread allows us to load the script's globals in the
    -- same Lua thread the action and rule functions will execute in.
    local co = create(main);
    local s, value, rule_return = resume(co, env, ...);
    if s and value ~= unique_value then
      print_debug(1,
    "A thread for %s yielded unexpectedly in the file or %s function:\n%s\n",
          self.filename, rule, traceback(co));
    elseif s and (rule_return or self.forced_to_run) then
      local thread = {
        close_handlers = {},
        co = co,
        env = env,
        identifier = tostring(co),
        info = format("'%s' (%s)", self.short_basename, tostring(co));
        parent = nil, -- placeholder
        script = self,
        type = script_type,
        worker = false,
      };
      thread.parent = thread;
      setmetatable(thread, Thread)
      return thread;
    elseif not s then
      log_error("A thread for %s failed to load in %s function:\n%s\n",
          self.filename, rule, traceback(co, tostring(value)));
    end
    return nil;
  end

  function Thread:new_worker (main, ...)
    local co = create(main);
    print_debug(2, "%s spawning new thread (%s).", self.parent.info, tostring(co));
    local thread = {
      args = {n = select("#", ...), ...},
      close_handlers = {},
      co = co,
      info = format("'%s' worker (%s)", self.short_basename, tostring(co));
      parent = self,
      worker = true,
    };
    setmetatable(thread, Worker)
    local function info ()
      return status(co), rawget(thread, "error");
    end
    return thread, info;
  end

  function Thread:resume ()
    return resume(self.co, unpack(self.args, 1, self.args.n));
  end

  function Thread:__index (key)
    return Thread[key] or self.script[key]
  end

  -- Script.new provides defaults for some of these.
  local required_fields = {
    action = "function",
    categories = "table",
    dependencies = "table",
  };
  local quiet_errors = {
    [REQUIRE_ERROR] = true,
  }

  -- script = Script.new(filename)
  -- Creates a new Script Class for the script.
  -- Arguments:
  --   filename  The filename (path) of the script to load.
  --   script_params  The script selection parameters table.
  --     Possible key/value pairs:
  --       selection: A string to indicate the script selection type.
  --                  "name": Selected by name or pattern.
  --                  "category" Selected by category.
  --                  "file path" Selected by file path.
  --                  "directory" Selected by directory.
  --       verbosity: A boolean, if set to true the script will get a
  --                verbosity boost. Scripts selected by name or
  --                file paths must set this to true.
  --       forced: A boolean to indicate if the script will be
  --               forced to run regardless to its rule results.
  --               (e.g. "+script").
  -- Returns:
  --   script  The script (class) created.
  function Script.new (filename, script_params)
    local script_params = script_params or {};
    assert(type(filename) == "string", "string expected");
    if not find(filename, "%.nse$") then
      log_error(
          "Warning: Loading '%s' -- the recommended file extension is '.nse'.",
          filename);
    end

    local basename = match(filename, "([^/\\]+)$") or filename;
    local short_basename = match(filename, "([^/\\]+)%.nse$") or
        match(filename, "([^/\\]+)%.[^.]*$") or filename;

    print_debug(2, "Script %s was selected by %s%s.",
        basename,
        script_params.selection or "(unknown)",
        script_params.forced and " and forced to run" or "");
    local script_closure_generator = loadscript(filename);
    -- Give the closure its own environment, with global access
    local env = {
      SCRIPT_PATH = filename,
      SCRIPT_NAME = short_basename,
      categories = {},
      dependencies = {},
    };
    setmetatable(env, {__index = _G});
    local script_closure = script_closure_generator(env);
    local co = create(script_closure); -- Create a garbage thread
    local status, e = resume(co); -- Get the globals it loads in env
    if not status then
      if quiet_errors[e] then
        print_verbose(1, "Failed to load '%s'.", filename);
        return nil;
      else
        log_error("Failed to load %s:\n%s", filename, traceback(co, e));
        error("could not load script");
      end
    end
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
      script_closure_generator = script_closure_generator,
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
      -- Make sure that the following are boolean types.
      selected_by_name = not not script_params.verbosity,
      forced_to_run = not not script_params.forced,
    };
    return setmetatable(script, Script)
  end

  Script.__index = Script;
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

  local db_env = {Entry = nil};
  local db_closure = assert(loadfile(script_database_path, "t", db_env),
    "database appears to be corrupt or out of date;\n"..
    "\tplease update using: nmap --script-updatedb");

  local chosen_scripts, files_loaded = {}, {};
  local entry_rules, used_rules, forced_rules = {}, {}, {};

  -- Tokens that are allowed in script rules (--script)
  local protected_lua_tokens = {
    ["and"] = true,
    ["or"] = true,
    ["not"] = true,
  };

  -- Was this category selection forced to run (e.g. "+script").
  -- Return:
  --    Boolean: True if it's forced otherwise false.
  --    String: The new cleaned string.
  local function is_forced_set (str)
    local specification = match(str, "^%+(.*)$");
    if specification then
      return true, specification;
    else
      return false, str;
    end
  end

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
    local original_rule = rule;
    local forced, rule = is_forced_set(rule);
    used_rules[rule] = false; -- has not been used yet
    forced_rules[rule] = forced;
    -- Here we escape backslashes which might appear in Windows filenames.
    rule = gsub(rule, "\\([^\\])", "\\\\%1");
    -- Globalize all `names`, all visible characters not ',', '(', ')', and ';'
    local globalized_rule =
        gsub(rule, "[\033-\039\042-\043\045-\058\060-\126]+", globalize);
    -- Precompile the globalized rule
    local env = {m = nil};
    local compiled_rule, err = load("return "..globalized_rule, "rule", "t", env);
    if not compiled_rule then
      err = err:match("rule\"]:%d+:(.+)$"); -- remove (luaL_)where in code
      error("Bad script rule:\n\t"..original_rule.." -> "..err);
    end
    -- These are used to reference and check all the rules later.
    entry_rules[globalized_rule] = {
      original_rule = rule,
      compiled_rule = compiled_rule,
      env = env,
    };
  end

  -- Checks if a given script, script_entry, should be loaded. A script_entry
  -- should be in the form: { filename = "name.nse", categories = { ... } }
  function db_env.Entry (script_entry)
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

    -- The script selection parameters table.
    local script_params = {};

    -- A matching function for each script rule.
    -- If the pattern directly matches a category (e.g. "all"), then
    -- we return true. Otherwise we test if it is a filename or if
    -- the script_entry.filename matches the pattern.
    local function m (pattern)
      -- Check categories
      if r_categories[lower(pattern)] then
        script_params.selection = "category";
        return true;
      end

      -- Check filename with wildcards
      pattern = gsub(pattern, "%.nse$", ""); -- remove optional extension
      pattern = gsub(pattern, "[%^%$%(%)%%%.%[%]%+%-%?]", "%%%1"); -- esc magic
      pattern = gsub(pattern, "%*", ".*"); -- change to Lua wildcard
      pattern = "^"..pattern.."$"; -- anchor to beginning and end
      if find(escaped_basename, pattern) then
        script_params.selection = "name";
        script_params.verbosity = true;
        return true;
      end

      return false;
    end

    for globalized_rule, rule_table in pairs(entry_rules) do
      -- Clear and set the environment of the compiled script rule
      rule_table.env.m = m;
      local status, found = pcall(rule_table.compiled_rule)
      rule_table.env.m = nil;
      if not status then
        error("Bad script rule:\n\t"..rule_table.original_rule..
              " -> script rule expression not supported.");
      end
      -- The script rule matches a category or a pattern
      if found then 
        used_rules[rule_table.original_rule] = true;
        script_params.forced = not not forced_rules[rule_table.original_rule];
        local t, path = cnse.fetchscript(filename);
        if t == "file" then
          if not files_loaded[path] then
            local script = Script.new(path, script_params)
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
  end

  db_closure(); -- Load the scripts

  -- Now load any scripts listed by name rather than by category.
  for rule, loaded in pairs(used_rules) do
    if not loaded then -- attempt to load the file/directory
      local script_params = {};
      script_params.forced = not not forced_rules[rule];
      local t, path = cnse.fetchscript(rule);
      if t == nil then -- perhaps omitted the extension?
        t, path = cnse.fetchscript(rule..".nse");
      end
      if t == nil then
        error("'"..rule.."' did not match a category, filename, or directory");
      elseif t == "file" and not files_loaded[path] then
        script_params.selection = "file path";
        script_params.verbosity = true;
        local script = Script.new(path, script_params);
        chosen_scripts[#chosen_scripts+1] = script;
        files_loaded[path] = true;
      elseif t == "directory" then
        for f in lfs.dir(path) do
          local file = path .."/".. f
          if find(file, "%.nse$") and not files_loaded[file] then
            script_params.selection = "directory";
            local script = Script.new(file, script_params);
            chosen_scripts[#chosen_scripts+1] = script;
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
local function run (threads_iter, hosts)
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
    return current and current.co;
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
    if current == nil then
      error "stdnse.new_thread can only be run from an active script"
    end
    local worker, info = current:new_worker(main, ...);
    total, all[worker.co], pending[worker.co], num_threads = total+1, worker, worker, num_threads+1;
    worker:start(timeouts);
    return worker.co, info;
  end);

  rawset(stdnse, "base", function ()
    return current and current.co;
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

      -- Threads may have zero, one, or two return values.
      local s, r1, r2 = thread:resume();
      if not s then -- script error...
        all[co], num_threads = nil, num_threads-1;
        if debugging() > 0 then
          thread:d("%THREAD_AGAINST threw an error!\n%s\n", traceback(co, tostring(r1)));
        else
          thread:set_output("ERROR: Script execution failed (use -d to debug)");
        end
        thread:close(timeouts, r1);
      elseif status(co) == "suspended" then
        if r1 == NSE_YIELD_VALUE then
          waiting[co] = thread;
        else
          all[co], num_threads = nil, num_threads-1;
          thread:d("%THREAD yielded unexpectedly and cannot be resumed.");
          thread:close();
        end
      elseif status(co) == "dead" then
        all[co], num_threads = nil, num_threads-1;
        thread:set_output(r1, r2);
        thread:d("Finished %THREAD_AGAINST.");
        thread:close(timeouts);
      end
      current = nil;
    end

    loop(50); -- Allow nsock to perform any pending callbacks
    -- Move pending threads back to running.
    for co, thread in pairs(pending) do
      pending[co], running[co] = nil, thread;
    end

    collectgarbage "step";
  end

  progress "endTask";
end

-- This function does the automatic formatting of Lua objects into strings, for
-- normal output and for the XML @output attribute. Each nested table is
-- indented by two spaces. Tables having a __tostring metamethod are converted
-- using tostring. Otherwise, integer keys are listed first and only their
-- value is shown; then string keys are shown prefixed by the key and a colon.
-- Any other kinds of keys. Anything that is not a table is converted to a
-- string with tostring.
local function format_table(obj, indent)
  indent = indent or "  ";
  if type(obj) == "table" then
    local mt = getmetatable(obj)
    if mt and mt["__tostring"] then
      -- Table obeys tostring, so use that.
      return tostring(obj)
    end

    local lines = {};
    -- Do integer keys.
    for _, v in ipairs(obj) do
      lines[#lines + 1] = indent .. format_table(v, indent .. "  ");
    end
    -- Do string keys.
    for k, v in pairs(obj) do
      if type(k) == "string" then
        lines[#lines + 1] = indent .. k .. ": " .. format_table(v, indent .. "  ");
      end
    end
    return "\n" .. concat(lines, "\n");
  else
    return tostring(obj);
  end
end
_R[FORMAT_TABLE] = format_table

local format_xml
local function format_xml_elem(obj, key)
  if key then
    key = cnse.protect_xml(tostring(key));
  end
  if type(obj) == "table" then
    cnse.xml_start_tag("table", {key=key});
    cnse.xml_newline();
  else
    cnse.xml_start_tag("elem", {key=key});
  end
  format_xml(obj);
  cnse.xml_end_tag();
  cnse.xml_newline();
end

-- This function writes an XML representation of a Lua object to the XML stream.
function format_xml(obj, key)
  if type(obj) == "table" then
    -- Do integer keys.
    for _, v in ipairs(obj) do
      format_xml_elem(v);
    end
    -- Do string keys.
    for k, v in pairs(obj) do
      if type(k) == "string" then
        format_xml_elem(v, k);
      end
    end
  else
    cnse.xml_write_escaped(cnse.protect_xml(tostring(obj)));
  end
end
_R[FORMAT_XML] = format_xml

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
    if script.description then
      log_write_raw("stdout", format_nsedoc(script.description, "  "));
    end
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

    if script.description then
      cnse.xml_start_tag("description");
      cnse.xml_write_escaped(script.description);
      cnse.xml_end_tag();
      cnse.xml_newline();
    end

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
  print_debug(1, "Script Arguments seen from CLI: %s", args);

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
  -- Check if user wants to read scriptargs from a file
  if cnse.scriptargsfile ~= nil then --scriptargsfile path/to/file
    local t, path = cnse.fetchfile_absolute(cnse.scriptargsfile)
    assert(t == 'file', format("%s is not a file", path))
    local argfile = assert(open(path, 'r'));
    local argstring = argfile:read("*a")
    argstring = gsub(argstring,"\n",",")
    local tmpargs = parse_table("{"..argstring.."}",1)
    for k,v in pairs(nmap.registry.args) do
      tmpargs[k] = v
    end
    nmap.registry.args = tmpargs
  end
  if debugging() >= 2 then
    local out = {}
    rawget(stdnse, "pretty_printer")(nmap.registry.args, function (s) out[#out+1] = s end)
    print_debug(2, concat(out))
  end
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
  for f in lfs.dir(path) do
    if match(f, '%.nse$') then
      scripts[#scripts+1] = path.."/"..f;
    end
  end
  sort(scripts);
  for i, script in ipairs(scripts) do
    script = Script.new(script);
    if ( script ) then
      sort(script.categories);
      db:write('Entry { filename = "', script.basename, '", ');
      db:write('categories = {');
      for j, category in ipairs(script.categories) do
        db:write(' "', lower(category), '",');
      end
      db:write(' } }\n');
    end
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

  if scantype == NSE_PRE_SCAN then
    print_verbose(1, "Script Pre-scanning.");
  elseif scantype == NSE_SCAN then
    if #hosts > 1 then
      print_verbose(1, "Script scanning %d hosts.", #hosts);
    elseif #hosts == 1 then
      print_verbose(1, "Script scanning %s.", hosts[1].ip);
    end
  elseif scantype == NSE_POST_SCAN then
    print_verbose(1, "Script Post-scanning.");
  end

  -- These functions do not exist until we are executing action functions.
  rawset(stdnse, "new_thread", nil)
  rawset(stdnse, "base", nil)

  for runlevel, scripts in ipairs(runlevels) do
    -- This iterator is passed to the run function. It returns one new script
    -- thread on demand until exhausted.
    local function threads_iter ()
      -- activate prerule scripts
      if scantype == NSE_PRE_SCAN then
        for _, script in ipairs(scripts) do
           local thread = script:new_thread("prerule");
           if thread then
             thread.args = {n = 0};
             yield(thread);
           end
        end
      -- activate hostrule and portrule scripts
      elseif scantype == NSE_SCAN then
        -- Check hostrules for this host.
        for j, host in ipairs(hosts) do
          for _, script in ipairs(scripts) do
            local thread = script:new_thread("hostrule", host_copy(host));
            if thread then
              thread.args, thread.host = {n = 1, host_copy(host)}, host;
              yield(thread);
            end
          end
          -- Check portrules for this host.
          for port in cnse.ports(host) do
            for _, script in ipairs(scripts) do
              local thread = script:new_thread("portrule", host_copy(host), tcopy(port));
              if thread then
                thread.args, thread.host, thread.port = {n = 2, host_copy(host), tcopy(port)}, host, port;
                yield(thread);
              end
            end
          end
        end
        -- activate postrule scripts
      elseif scantype == NSE_POST_SCAN then
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
    run(wrap(threads_iter), hosts)
  end

  collectgarbage "collect";
end

return main;
