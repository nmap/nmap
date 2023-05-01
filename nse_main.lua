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
-- these attack vectors is more to show the difficulty in accidentally
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
if tonumber(MAJOR.."."..MINOR) < 5.4 then
  error "NSE requires Lua 5.4 or newer. It looks like you're using an older version of nmap."
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
local PARALLELISM = "NSE_PARALLELISM";

-- Unique value indicating the action function is going to run.
local ACTION_STARTING = {};

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
local upper = string.upper;

local table = require "table";
local concat = table.concat;
local insert = table.insert;
local pack = table.pack;
local remove = table.remove;
local sort = table.sort;
local unpack = table.unpack;

local os = require "os"
local time = os.time
local difftime = os.difftime

do -- Add loader to look in nselib/?.lua (nselib/ can be in multiple places)
  local function loader (lib)
    lib = lib:gsub("%.", "/"); -- change Lua "module separator" to directory separator
    local name = "nselib/"..lib..".lua";
    local type, path = cnse.fetchfile_absolute(name);
    if type == "file" then
      return assert(loadfile(path));
    else
      return "\n\tNSE failed to find "..name.." in search paths.";
    end
  end
  insert(package.searchers, 1, loader);
end

local lpeg = require "lpeg";
local U = require "lpeg-utility"
local locale = lpeg.locale;
local P = lpeg.P;
local R = lpeg.R;
local S = lpeg.S;
local V = lpeg.V;
local C = lpeg.C;
local Cb = lpeg.Cb;
local Cc = lpeg.Cc;
local Cf = lpeg.Cf;
local Cg = lpeg.Cg;
local Ct = lpeg.Ct;

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
local script_database = {Entry = nil,chunk = nil}

local script_help = cnse.scripthelp;

-- NSE_YIELD_VALUE
-- This is the table C uses to yield a thread with a unique value to
-- differentiate between yields initiated by NSE or regular coroutine yields.
local NSE_YIELD_VALUE = {};

do
  -- This is the method by which we allow a script to have nested
  -- coroutines. If a sub-thread yields in an NSE function such as
  -- nsock.connect, then we propagate the yield up. These replacements
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

-- Check for and warn about some known bad behaviors
if ("test"):gsub(".*$", "x") == "xx" then
  log_error("Known bug in string.gsub in Lua 5.3 before 5.3.3 will cause bugs in NSE scripts.")
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
local tcopy = require "tableaux".tcopy

-- copies the host table while preserving the registry
local function host_copy(t)
  local h = tcopy(t)
  h.registry = t.registry
  return h
end

-- Return a pattern which matches a "keyword" literal, case insensitive.
local memo_K = {}
local function K (a)
  local kw = memo_K[a]
  if not kw then
    kw = U.caseless(a) * #(V "space" + S"()," + P(-1))
    memo_K[a] = kw
  end
  return kw
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

  local function replace(fmt, pattern, repl)
    -- Escape each % twice: once for gsub, and once for print_debug.
    local r = gsub(repl, "%%", "%%%%%%%%")
    return gsub(fmt, pattern, r);
  end
  -- Thread:d()
  -- Outputs debug information at level 1 or higher.
  -- Changes "%THREAD" with an appropriate identifier for the debug level
  function Thread:d (fmt, ...)
    local against = against_name(self.host, self.port);
    local dbg = debugging()
    if dbg > 1 then
      fmt = replace(fmt, "%%THREAD_AGAINST", self.info..against);
      fmt = replace(fmt, "%%THREAD", self.info);
    elseif dbg == 1 then
      fmt = replace(fmt, "%%THREAD_AGAINST", self.short_basename..against);
      fmt = replace(fmt, "%%THREAD", self.short_basename);
    else
      return
    end
    -- debugging() >= 1
    log_write("stdout", format(fmt, ...));
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
    -- checking whether user gave --script-timeout option or not
    if cnse.script_timeout and cnse.script_timeout > 0 and
      -- comparing script's timeout with time elapsed
      cnse.script_timeout < difftime(time(), self.start_time) then
      return true
    end
    if self.host then
      return cnse.timedOut(self.host)
    end
    return false
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
    if self.host then
      timeouts[self.host] = timeouts[self.host] or {};
      timeouts[self.host][self.co] = true;
    end
    -- storing script's start time so as to account for script's timeout later
    if self.worker then
      self.start_time = self.parent.start_time
    else
      self.start_time = time()
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

    -- Rebuild the environment for the running thread.
    local env = {
        SCRIPT_PATH = self.filename,
        SCRIPT_NAME = self.short_basename,
        SCRIPT_TYPE = script_type,
    };
    setmetatable(env, {__index = _G});
    local forced = self.forced_to_run;
    local script_closure_generator = self.script_closure_generator;
    local function main (...)
      local _ENV = env; -- change the environment
      -- Load the script's globals in the same Lua thread the action and rule
      -- functions will execute in.
      script_closure_generator(_ENV)();
      if forced or _ENV[rule](...) then
        yield(ACTION_STARTING)
        return action(...)
      end
    end

    local co = create(main);
    local thread = {
      action_started = false,
      args = pack(...),
      close_handlers = {},
      co = co,
      env = env,
      identifier = tostring(co),
      info = format("%s M:%s", self.id, match(tostring(co), "^thread: 0?[xX]?(.*)"));
      parent = nil, -- placeholder
      script = self,
      type = script_type,
      worker = false,
      start_time = 0, --for script timeout
    };
    thread.parent = thread;
    setmetatable(thread, Thread)
    return thread;
  end

  function Thread:new_worker (main, ...)
    local co = create(main);
    print_debug(2, "%s spawning new thread (%s).", self.parent.info, tostring(co));
    local thread = {
      args = pack(...),
      close_handlers = {},
      co = co,
      info = format("%s W:%s", self.id, match(tostring(co), "^thread: 0?[xX]?(.*)"));
      parent = self,
      worker = true,
      start_time = 0,
    };
    setmetatable(thread, Worker)
    local function info ()
      return status(co), rawget(thread, "error");
    end
    return thread, info;
  end

  function Thread:resume (timeouts)
    local ok, r1, r2 = resume(self.co, unpack(self.args, 1, self.args.n));
    local status = status(self.co);
    if ok and r1 == ACTION_STARTING then
      self:d("Starting %THREAD_AGAINST.");
      self.action_started = true
      return self:resume(timeouts);
    elseif not ok then
      -- Extend this to create new types of errors with custom handling.
      -- nmap.new_try does equivalent of: error({errtype="nmap.new_try", message="TIMEOUT"})
      if type(r1) == "table" and r1.errtype == "nmap.new_try" then
        -- nmap.new_try "exception" is closing the script
        if debugging() > 0 then
          self:d("Finished %THREAD_AGAINST. Reason: %s\n", r1.message);
        end
        r1 = r1.message
      elseif debugging() > 0 then
        self:d("%THREAD_AGAINST threw an error!\n%s\n", traceback(self.co, tostring(r1)));
      else
        self:set_output("ERROR: Script execution failed (use -d to debug)");
      end
      self:close(timeouts, r1);
      return false
    elseif status == "suspended" then
      if r1 == NSE_YIELD_VALUE then
        return true
      else
        self:d("%THREAD yielded unexpectedly and cannot be resumed.");
        self:close(timeouts, "yielded unexpectedly and cannot be resumed");
        return false
      end
    elseif status == "dead" then
      if self.action_started then
        self:set_output(r1, r2);
        -- -d1 = report finished scripts. -d2 = report finished threads
        if not self.worker or debugging() > 1 then
          self:d("Finished %THREAD_AGAINST.");
        end
      end
      self:close(timeouts);
    end
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
  assert(script_database.chunk, "Script database not loaded")

  local chosen_scripts, files_loaded = {}, {};
  local used_rules, forced_rules = {}, {};

  for i, rule in ipairs(rules) do
    -- A rule (usually filename) is forced if it starts with "+"
    local forced, rule = match(rule, "^%s*(%+?)%s*(.-)%s*$"); -- strip surrounding whitespace
    if rule and rule ~= "" then
      used_rules[rule] = false; -- has not been used yet
      forced_rules[rule] = (forced == "+");
      rules[i] = rule;
    end
  end

  local pre_T = locale {
    V "space"^0 * V "expression" * V "space"^0 * P(-1);

    expression = V "disjunct" + V "conjunct" + V "value";
    disjunct = (V "conjunct" + V "value") * V "space"^0 * K "or" * V "space"^0 * V "expression" / function (a, b) return a or b end;
    conjunct = V "value" * V "space"^0 * K "and" * V "space"^0 * V "expression" / function (a, b) return a and b end;
    value = K "not" * V "space"^0 * V "value" / function (a) return not a end +
    P "(" * V "space"^0 * V "expression" * V "space"^0 * P ")" +
    K "true" * Cc(true) +
    K "false" * Cc(false) +
    V "category" +
    V "path";
  }
  -- cache/memoize result of "glob-izing" a word in a rule.
  local globs = {}
  setmetatable(globs, {
      __index = function(t, path)
        local glob = gsub(path, "%.nse$", ""); -- remove optional extension
        glob = gsub(glob, "[%^%$%(%)%%%.%[%]%+%-%?]", "%%%1"); -- esc magic
        glob = gsub(glob, "%*", ".*"); -- change to Lua wildcard
        glob = "^"..glob.."$"; -- anchor to beginning and end
        t[path] = glob
        return glob
      end,
    })
  -- Checks if a given script, script_entry, should be loaded. A script_entry
  -- should be in the form: { filename = "name.nse", categories = { ... } }
  script_database.Entry = function (script_entry)
    local categories = rawget(script_entry, "categories");
    local filename = rawget(script_entry, "filename");
    assert(type(categories) == "table" and type(filename) == "string", "script database appears corrupt, try `nmap --script-updatedb`");
    local escaped_basename = match(filename, "([^/\\]-)%.nse$") or match(filename, "([^/\\]-)$");
    local selected_by_name = false;
    -- The script selection parameters table.
    local script_params = {};

    -- Test if path is a glob pattern that matches script_entry.filename.
    local function match_script (path)
      local found = not not find(escaped_basename, globs[path]);
      selected_by_name = selected_by_name or found;
      return found;
    end

    local my_cats = K "all" * Cc(true) -- pseudo-category "all" matches everything
    for i, category in ipairs(categories) do
      assert(type(category) == "string", "bad entry in script database");
      my_cats = my_cats + K(category) * Cc(true);
    end

    pre_T.path = R("\033\039", "\042\126")^1 / match_script; -- all graphical characters not '(', ')'
    pre_T.category = my_cats

    local T = P(pre_T)

    for i, rule in ipairs(rules) do
      selected_by_name = false;
      if T:match(rule) then
        used_rules[rule] = true;
        script_params.forced = not not forced_rules[rule];
        if selected_by_name then
          script_params.selection = "name"
          script_params.verbosity = true
        else
          script_params.selection = "category"
        end
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

  script_database.chunk() -- Load the scripts

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
        -- Avoid erroring if -sV but no scripts are present
        if not (cnse.scriptversion and rule == "version") then
          error("'"..rule.."' did not match a category, filename, or directory");
        end
      elseif t == "bare_directory" then
        error("directory '"..path.."' found, but will not match without '/'")
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
    assert(name_script[script.short_basename] == nil,
      ("duplicate script ID: '%s'"):format(script.short_basename));
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
local function run (threads_iter)
  -- running scripts may be resumed at any time. waiting scripts are
  -- yielded until Nsock wakes them. After being awakened with
  -- nse_restore, waiting threads become pending and later are moved all
  -- at once back to running. pending is used because we cannot modify
  -- running during traversal.
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
        pending[co].args = pack(...);
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
  rawset(stdnse, "gettid", function ()
    return current and current.identifier;
  end);
  rawset(stdnse, "getid", function ()
    return current and current.id;
  end);
  rawset(stdnse, "getinfo", function ()
    return current and current.info;
  end);
  rawset(stdnse, "gethostport", function ()
    if current then
        return current.host, current.port;
    end
  end);
  rawset(stdnse, "isworker", function ()
    return current and current.worker;
  end);

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
    -- total may be 0 if no scripts are running in this phase
    if total > 0 and cnse.key_was_pressed() then
      print_verbose(1, "Active NSE Script Threads: %d (%d waiting)",
          nr+nw, nw);
      progress("printStats", 1-(nr+nw)/total);
      if debugging() >= 2 then
        for co, thread in pairs(running) do
          thread:d("Running: %THREAD_AGAINST\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
        for co, thread in pairs(waiting) do
          thread:d("Waiting: %THREAD_AGAINST\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
      elseif debugging() >= 1 then
        local display = {}
        local limit = 0
        for co, thread in pairs(running) do
          local this = display[thread.short_basename]
          if not this then
            this = {}
            limit = limit + 1
            if limit > 5 then
              -- Only print stats if 5 or fewer scripts remaining
              break
            end
          end
          this[1] = (this[1] or 0) + 1
          display[thread.short_basename] = this
        end
        for co, thread in pairs(waiting) do
          local this = display[thread.short_basename]
          if not this then
            this = {}
            limit = limit + 1
            if limit > 5 then
              -- Only print stats if 5 or fewer scripts remaining
              break
            end
          end
          this[2] = (this[2] or 0) + 1
          display[thread.short_basename] = this
        end
        if limit <= 5 then
          for name, stats in pairs(display) do
            print_debug(1, "Script %s: %d threads running, %d threads waiting",
              name, stats[1] or 0, stats[2] or 0)
          end
        end
      end
    elseif total > 0 and progress "mayBePrinted" then
      if verbosity() > 1 or debugging() > 0 then
        progress("printStats", 1-(nr+nw)/total);
      else
        progress("printStatsIfNecessary", 1-(nr+nw)/total);
      end
    end

    local orphans = true
    -- Checked for timed-out scripts and hosts.
    for co, thread in pairs(waiting) do
      if thread:timed_out() then
        waiting[co], all[co], num_threads = nil, nil, num_threads-1;
        thread:d("%THREAD_AGAINST timed out")
        thread:close(timeouts, "timed out");
      elseif not thread.worker then
        orphans = false
      end
    end

    for co, thread in pairs(running) do
      current, running[co] = thread, nil;
      thread:start_time_out_clock();

      if thread:resume(timeouts) then
        waiting[co] = thread;
        if not thread.worker then
          orphans = false
        end
      else
        all[co], num_threads = nil, num_threads-1;
      end
      current = nil;
    end

    loop(50); -- Allow nsock to perform any pending callbacks
    -- Move pending threads back to running.
    for co, thread in pairs(pending) do
      pending[co], running[co] = nil, thread;
      if not thread.worker then
        orphans = false
      end
    end

    collectgarbage "step";
    -- If we didn't see at least one non-worker thread, then any remaining are orphaned.
    if num_threads > 0 and orphans then
      print_debug(1, "%d orphans left!", total)
      break
    end
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
      lines[#lines + 1] = "\n"
      lines[#lines + 1] = indent
      lines[#lines + 1] = format_table(v, indent .. "  ")
    end
    -- Do string keys.
    for k, v in pairs(obj) do
      if type(k) == "string" then
        lines[#lines + 1] = "\n"
        lines[#lines + 1] = indent
        lines[#lines + 1] = k
        lines[#lines + 1] = ": "
        lines[#lines + 1] = format_table(v, indent .. "  ")
      end
    end
    return concat(lines);
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

nmap.registry.args = {};
do
  local args = {};

  if cnse.scriptargsfile then
    local t, path = cnse.fetchfile_absolute(cnse.scriptargsfile)
    assert(t == 'file', format("%s is not a file", path))
    print_debug(1, "Loading script-args from file `%s'", cnse.scriptargsfile);
    args[#args+1] = assert(assert(open(path, 'r')):read "*a"):gsub(",*$", "");
  end

  if cnse.scriptargs then -- Load script arguments (--script-args)
    print_debug(1, "Arguments from CLI: %s", cnse.scriptargs);
    args[#args+1] = cnse.scriptargs;
  end

  if cnse.script_timeout and cnse.script_timeout > 0 then
    print_debug(1, "Set script-timeout as: %d seconds", cnse.script_timeout);
  end

  args = concat(args, ",");
  if #args > 0 then
    print_debug(1, "Arguments parsed: %s", args);
    local function set (t, a, b)
      if b == nil then
        insert(t, a);
        return t;
       else
        return rawset(t, a, b);
      end
    end
    local parser = locale {
      V "space"^0 * V "table" * V "space"^0,
      table = Cf(Ct "" * P "{" * V "space"^0 * (V "fieldlst")^-1 * V "space"^0 * P "}", set);
      hws = V "space" - P "\n", -- horizontal whitespace
      fieldlst = V "field" * (V "hws"^0 * S "\n," * V "space"^0 * V "field")^0;
      field = V "kv" + V "av";
      kv = Cg(V "string" * V "hws"^0 * P "=" * V "hws"^0 * V "value");
      av = Cg(V "value");
      value = V "table" + V "string";
      string = V "qstring" + V "uqstring";
      qstring = U.escaped_quote('"') + U.escaped_quote("'");
      uqstring = V "hws"^0 * C((P(1) - V "hws"^0 * S "\n,{}=")^0) * V "hws"^0; -- everything but '\n,{}=', do not capture final space
    };
    --U.debug(parser,function(...)return print_debug(1,...)end)
    parser = assert(P(parser));
    nmap.registry.args = parser:match("{"..args.."}");
    if not nmap.registry.args then
      log_write("stdout", "args = "..args);
      error "arguments did not parse!"
    end
    if debugging() >= 2 then
      local out = {}
      rawget(stdnse, "pretty_printer")(nmap.registry.args, function (s) out[#out+1] = s end)
      print_debug(2, "%s", concat(out))
    end
  end
end

-- Update Missing Script Database?
if script_database_type ~= "file" then
  print_verbose(1, "Script Database missing, will create new one.");
  script_database_update = true; -- force update
else
  local err
  script_database.chunk, err = loadfile(script_database_path, "t", script_database)
  if not script_database.chunk then
    log_write("stdout",
      "NSE script database appears to be corrupt or out of date;\n"..
      "\tplease update using: nmap --script-updatedb")
    print_debug(1, "loadfile error: %s", err)
    script_database_update = true
  end
end

if script_database_update then
  log_write("stdout", "Updating rule database.");
  local t, path = cnse.fetchfile_absolute('scripts/'); -- fetch script directory
  assert(t == 'directory', 'could not locate scripts directory');
  script_database_path = path .. "script.db"
  local scripts = {};
  for f in lfs.dir(path) do
    if match(f, '%.nse$') then
      scripts[#scripts+1] = path.."/"..f;
    end
  end
  sort(scripts);
  local db_text = {}
  local db_params = {selection = "script.db update"}
  for i, script in ipairs(scripts) do
    script = Script.new(script, db_params);
    if ( script ) then
      sort(script.categories);
      db_text[#db_text+1] = format('Entry { filename = "%s", categories = {', script.basename)
      for j, category in ipairs(script.categories) do
        db_text[#db_text+1] = format(' "%s",', lower(category))
      end
      db_text[#db_text+1] = ' } }\n'
    end
  end
  db_text = concat(db_text)
  local db, status, err
  script_database.chunk, err = load(db_text, "script.db", "t", script_database)
  if not script_database.chunk then
    error("Script database corrupt: " .. err)
  end
  db, err = open(script_database_path, 'w')
  if db then
    status, err = db:write(db_text)
    db:close();
  end
  if status then
    log_write("stdout", "Script Database updated successfully.");
  else
    (cnse.scriptupdatedb and error or log_error)("Could not save script.db: " .. err)
  end
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

-- This iterator is passed to the run function. It returns one new script
-- thread on demand until exhausted.
local threads_iters = {
  NSE_PRE_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      for _, script in ipairs(scripts) do
        local thread = script:new_thread("prerule");
        if thread then
          yield(thread)
        end
      end
    end
  end,
  NSE_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      -- Check hostrules for this host.
      for j, host in ipairs(hosts) do
        for _, script in ipairs(scripts) do
          local thread = script:new_thread("hostrule", host_copy(host));
          if thread then
            thread.host = host;
            yield(thread);
          end
        end
        -- Check portrules for this host.
        for port in cnse.ports(host) do
          for _, script in ipairs(scripts) do
            local thread = script:new_thread("portrule", host_copy(host), tcopy(port));
            if thread then
              thread.host, thread.port = host, port;
              yield(thread);
            end
          end
        end
      end
    end
  end,
  NSE_POST_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      for _, script in ipairs(scripts) do
        local thread = script:new_thread("postrule");
        if thread then
          yield(thread);
        end
      end
    end
  end,
}

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

  if _R[PARALLELISM] > CONCURRENCY_LIMIT then
    CONCURRENCY_LIMIT = _R[PARALLELISM];
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

  for runlevel, scripts in ipairs(runlevels) do
    local threads_iter = assert(threads_iters[scantype](hosts, scripts))
    print_verbose(2, "Starting runlevel %u (of %u) scan.", runlevel, #runlevels);
    run(wrap(threads_iter))
  end

  collectgarbage "collect";
end

return main;
