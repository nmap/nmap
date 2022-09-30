---
-- Standard Nmap Scripting Engine functions. This module contains various handy
-- functions that are too small to justify modules of their own.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name stdnse

local _G = require "_G"
local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local string = require "string"
local table = require "table"
local assert = assert;
local error = error;
local getmetatable = getmetatable;
local ipairs = ipairs
local pairs = pairs
local next = next
local rawset = rawset
local require = require;
local select = select
local setmetatable = setmetatable;
local tonumber = tonumber;
local tostring = tostring;
local print = print;
local type = type
local pcall = pcall

local ceil = math.ceil
local max = math.max

local format = string.format;
local rep = string.rep
local match = string.match
local find = string.find
local sub = string.sub
local gsub = string.gsub
local char = string.char
local byte = string.byte
local gmatch = string.gmatch

local concat = table.concat;
local insert = table.insert;
local remove = table.remove;
local pack = table.pack;
local unpack = table.unpack;

local EMPTY = {}; -- Empty constant table

_ENV = require "strict" {};

--- Sleeps for a given amount of time.
--
-- This causes the program to yield control and not regain it until the time
-- period has elapsed. The time may have a fractional part. Internally, the
-- timer provides millisecond resolution.
-- @name sleep
-- @class function
-- @param t Time to sleep, in seconds.
-- @usage stdnse.sleep(1.5)
_ENV.sleep = nmap.socket.sleep;

-- These stub functions get overwritten by the script run loop in nse_main.lua
-- These empty stubs will be used if a library calls stdnse.debug while loading
_ENV.getid = function () return end
_ENV.getinfo = function () return end
_ENV.gethostport = function () return end

local function debug (level, ...)
  if type(level) ~= "number" then
    return debug(1, level, ...)
  end
  local current = nmap.debugging()
  if level <= current then
    local host, port = gethostport()
    local prefix = ( (current >= 2 and getinfo or getid)() or "")
    .. (host and " "..host.ip .. (port and ":"..port.number or "") or "")
    if prefix ~= "" then
      nmap.log_write("stdout", "[" .. prefix .. "] " .. format(...))
    else
      nmap.log_write("stdout", format(...))
    end
  end
end

---
-- Prints a formatted debug message if the current debugging level is greater
-- than or equal to a given level.
--
-- This is a convenience wrapper around <code>nmap.log_write</code>. The first
-- optional numeric argument, <code>level</code>, is used as the debugging level
-- necessary to print the message (it defaults to 1 if omitted). All remaining
-- arguments are processed with Lua's <code>string.format</code> function.
--
-- If known, the output includes some context based information: the script
-- identifier and the target ip/port (if there is one). If the debug level is
-- at least 2, it also prints the base thread identifier and whether it is a
-- worker thread or the controller thread.
--
-- @class function
-- @name debug
-- @param level Optional debugging level.
-- @param fmt Format string.
-- @param ... Arguments to format.
_ENV.debug = debug

--Aliases for particular debug levels
function debug1 (...) return debug(1, ...) end
function debug2 (...) return debug(2, ...) end
function debug3 (...) return debug(3, ...) end
function debug4 (...) return debug(4, ...) end
function debug5 (...) return debug(5, ...) end

---
-- Deprecated version of debug(), kept for now to prevent the script id from being
-- printed twice. Scripts should use debug() and not pass SCRIPT_NAME
print_debug = function(level, fmt, ...)
  local l, d = tonumber(level), nmap.debugging();
  if l and l <= d then
    nmap.log_write("stdout", format(fmt, ...));
  elseif not l and 1 <= d then
    nmap.log_write("stdout", format(level, fmt, ...));
  end
end

local function verbose (level, ...)
  if type(level) ~= "number" then
    return verbose(1, level, ...)
  end
  local current = nmap.verbosity()
  if level <= current then
    local prefix
    if current >= 2 then
      local host, port = gethostport()
      prefix = (getid() or "")
      .. (host and " "..host.ip .. (port and ":"..port.number or "") or "")
    else
      prefix = getid() or ""
    end
    if prefix ~= "" then
      nmap.log_write("stdout", "[" .. prefix .. "] " .. format(...))
    else
      nmap.log_write("stdout", format(...))
    end
  end
end

---
-- Prints a formatted verbosity message if the current verbosity level is greater
-- than or equal to a given level.
--
-- This is a convenience wrapper around <code>nmap.log_write</code>. The first
-- optional numeric argument, <code>level</code>, is used as the verbosity level
-- necessary to print the message (it defaults to 1 if omitted). All remaining
-- arguments are processed with Lua's <code>string.format</code> function.
--
-- If known, the output includes some context based information: the script
-- identifier. If the verbosity level is at least 2, it also prints the target
-- ip/port (if there is one)
--
-- @class function
-- @name verbose
-- @param level Optional verbosity level.
-- @param fmt Format string.
-- @param ... Arguments to format.
_ENV.verbose = verbose

--Aliases for particular verbosity levels
function verbose1 (...) return verbose(1, ...) end
function verbose2 (...) return verbose(2, ...) end
function verbose3 (...) return verbose(3, ...) end
function verbose4 (...) return verbose(4, ...) end
function verbose5 (...) return verbose(5, ...) end

---
-- Deprecated version of verbose(), kept for now to prevent the script id from being
-- printed twice. Scripts should use verbose() and not pass SCRIPT_NAME
print_verbose = function(level, fmt, ...)
  local l, d = tonumber(level), nmap.verbosity();
  if l and l <= d then
    nmap.log_write("stdout", format(fmt, ...));
  elseif not l and 1 <= d then
    nmap.log_write("stdout", format(level, fmt, ...));
  end
end

--- Return a wrapper closure around a socket that buffers socket reads into
-- chunks separated by a pattern.
--
-- This function operates on a socket attempting to read data. It separates the
-- data by <code>sep</code> and, for each invocation, returns a piece of the
-- separated data. Typically this is used to iterate over the lines of data
-- received from a socket (<code>sep = "\r?\n"</code>). The returned string
-- does not include the separator. It will return the final data even if it is
-- not followed by the separator. Once an error or EOF is reached, it returns
-- <code>nil, msg</code>. <code>msg</code> is what is returned by
-- <code>nmap.receive_lines</code>.
-- @param socket Socket for the buffer.
-- @param sep Separator for the buffered reads.
-- @return Data from socket reads or <code>nil</code> on EOF or error.
-- @return Error message, as with <code>receive_lines</code>.
function make_buffer(socket, sep)
  local point, left, buffer, done, msg = 1, "";
  local function self()
    if done then
      return nil, msg; -- must be nil for stdnse.lines (below)
    elseif not buffer then
      local status, str = socket:receive();
      if not status then
        if #left > 0 then
          done, msg = not status, str;
          return left;
        else
          return status, str;
        end
      else
        buffer = left..str;
        return self();
      end
    else
      local i, j = find(buffer, sep, point);
      if i then
        local ret = sub(buffer, point, i-1);
        point = j + 1;
        return ret;
      else
        point, left, buffer = 1, sub(buffer, point), nil;
        return self();
      end
    end
  end
  return self;
end

--[[ This function may be usable in Lua 5.2
function lines(socket)
  return make_buffer(socket, "\r?\n"), nil, nil;
end --]]

do
  local t = {
    ["0"] = "0000",
    ["1"] = "0001",
    ["2"] = "0010",
    ["3"] = "0011",
    ["4"] = "0100",
    ["5"] = "0101",
    ["6"] = "0110",
    ["7"] = "0111",
    ["8"] = "1000",
    ["9"] = "1001",
    a = "1010",
    b = "1011",
    c = "1100",
    d = "1101",
    e = "1110",
    f = "1111"
  };

--- Converts the given number, n, to a string in a binary number format (12
-- becomes "1100"). Leading 0s not stripped.
-- @param n Number to convert.
-- @return String in binary format.
  function tobinary(n)
    -- enforced by string.format: assert(tonumber(n), "number expected");
    return gsub(format("%x", n), "%w", t)
  end
end

--- Converts the given number, n, to a string in an octal number format (12
-- becomes "14").
-- @param n Number to convert.
-- @return String in octal format.
function tooctal(n)
  -- enforced by string.format: assert(tonumber(n), "number expected");
  return format("%o", n)
end

local tohex_helper =  function(b)
  return format("%02x", byte(b))
end
--- Encode a string or integer in hexadecimal (12 becomes "c", "AB" becomes
-- "4142").
--
-- An optional second argument is a table with formatting options. The possible
-- fields in this table are
-- * <code>separator</code>: A string to use to separate groups of digits.
-- * <code>group</code>: The size of each group of digits between separators. Defaults to 2, but has no effect if <code>separator</code> is not also given.
-- @usage
-- stdnse.tohex("abc") --> "616263"
-- stdnse.tohex("abc", {separator = ":"}) --> "61:62:63"
-- stdnse.tohex("abc", {separator = ":", group = 4}) --> "61:6263"
-- stdnse.tohex(123456) --> "1e240"
-- stdnse.tohex(123456, {separator = ":"}) --> "1:e2:40"
-- stdnse.tohex(123456, {separator = ":", group = 4}) --> "1:e240"
-- @param s String or number to be encoded.
-- @param options Table specifying formatting options.
-- @return String in hexadecimal format.
function tohex( s, options )
  options = options or EMPTY
  local separator = options.separator
  local hex

  if type( s ) == "number" then
    hex = format("%x", s)
  elseif type( s ) == 'string' then
    hex = gsub(s, ".", tohex_helper)
  else
    error( "Type not supported in tohex(): " .. type(s), 2 )
  end

  -- format hex if we got a separator
  if separator then
    local group = options.group or 2
    local subs = 0
    local pat = "(%x)(" .. rep("[^:]", group) .. ")%f[\0:]"
    repeat
      hex, subs = gsub(hex, pat, "%1:%2")
    until subs == 0
  end

  return hex
end


local fromhex_helper = function (h)
  return char(tonumber(h, 16))
end
---Decode a hexadecimal string to raw bytes
--
-- The string can contain any amount of whitespace and capital or lowercase
-- hexadecimal digits. There must be an even number of hex digits, since it
-- takes 2 hex digits to make a byte.
--
-- @param hex A string in hexadecimal representation
-- @return A string of bytes or nil if string could not be decoded
-- @return Error message if string could not be decoded
function fromhex (hex)
  local p = find(hex, "[^%x%s]")
  if p then
    return nil, "Invalid hexadecimal digits at position " .. p
  end
  hex = gsub(hex, "%s+", "")
  if #hex % 2 ~= 0 then
    return nil, "Odd number of hexadecimal digits"
  end
  return gsub(hex, "..", fromhex_helper)
end

local colonsep = {separator=":"}
---Format a MAC address as colon-separated hex bytes.
--@param mac The MAC address in binary, such as <code>host.mac_addr</code>
--@return The MAC address in XX:XX:XX:XX:XX:XX format
function format_mac(mac)
  return tohex(mac, colonsep)
end

---Either return the string itself, or return "<blank>" (or the value of the second parameter) if the string
-- was blank or nil.
--
--@param string The base string.
--@param blank  The string to return if <code>string</code> was blank
--@return Either <code>string</code> or, if it was blank, <code>blank</code>
function string_or_blank(string, blank)
  if(string == nil or string == "") then
    if(blank == nil) then
      return "<blank>"
    else
      return blank
    end
  else
    return string
  end
end

local timespec_multipliers = {[""] = 1, s = 1, m = 60, h = 60 * 60, ms = 0.001}
---
-- Parses a time duration specification, which is a number followed by a
-- unit, and returns a number of seconds.
--
-- The unit is optional and defaults to seconds. The possible units
-- (case-insensitive) are
-- * <code>ms</code>: milliseconds,
-- * <code>s</code>: seconds,
-- * <code>m</code>: minutes,
-- * <code>h</code>: hours.
-- In case of a parsing error, the function returns <code>nil</code>
-- followed by an error message.
--
-- @usage
-- parse_timespec("10") --> 10
-- parse_timespec("10ms") --> 0.01
-- parse_timespec("10s") --> 10
-- parse_timespec("10m") --> 600
-- parse_timespec("10h") --> 36000
-- parse_timespec("10z") --> nil, "Can't parse time specification \"10z\" (bad unit \"z\")"
--
-- @param timespec A time specification string.
-- @return A number of seconds, or <code>nil</code> followed by an error
-- message.
function parse_timespec(timespec)
  if timespec == nil then return nil, "Can't parse nil timespec" end
  local n, unit, t, m

  n, unit = match(timespec, "^([%d.]+)(.*)$")
  if not n then
    return nil, format("Can't parse time specification \"%s\"", timespec)
  end

  t = tonumber(n)
  if not t then
    return nil, format("Can't parse time specification \"%s\" (bad number \"%s\")", timespec, n)
  end

  m = timespec_multipliers[unit]
  if not m then
    return nil, format("Can't parse time specification \"%s\" (bad unit \"%s\")", timespec, unit)
  end

  return t * m
end

--- Returns the current time in milliseconds since the epoch
-- @return The current time in milliseconds since the epoch
function clock_ms()
  return nmap.clock() * 1000
end

--- Returns the current time in microseconds since the epoch
-- @return The current time in microseconds since the epoch
function clock_us()
  return nmap.clock() * 1000000
end

---Get the indentation symbols at a given level.
local function format_get_indent(indent)
  return rep("  ", #indent)
end

-- A helper for format_output (see below).
local function format_output_sub(status, data, indent)
  if (#data == 0) then
    return ""
  end

  -- Used to put 'ERROR: ' in front of all lines on error messages
  local prefix = ""
  -- Initialize the output string to blank (or, if we're at the top, add a newline)
  local output = {}
  if(not(indent)) then
    insert(output, '\n')
  end

  if(not(status)) then
    if(nmap.debugging() < 1) then
      return nil
    end
    prefix = "ERROR: "
  end

  -- If a string was passed, turn it into a table
  if(type(data) == 'string') then
    data = {data}
  end

  -- Make sure we have an indent value
  indent = indent or {}

  if(data['name']) then
    if(data['warning'] and nmap.debugging() > 0) then
      insert(output, format("%s%s%s (WARNING: %s)\n",
                        format_get_indent(indent), prefix,
                        data['name'], data['warning']))
    else
      insert(output, format("%s%s%s\n",
                        format_get_indent(indent), prefix,
                        data['name']))
    end
  elseif(data['warning'] and nmap.debugging() > 0) then
    insert(output, format("%s%s(WARNING: %s)\n",
                      format_get_indent(indent), prefix,
                      data['warning']))
  end

  for i, value in ipairs(data) do
    if(type(value) == 'table') then
      -- Do a shallow copy of indent
      local new_indent = {}
      for _, v in ipairs(indent) do
        insert(new_indent, v)
      end

      if(i ~= #data) then
        insert(new_indent, false)
      else
        insert(new_indent, true)
      end

      insert(output, format_output_sub(status, value, new_indent))

    elseif(type(value) == 'string') then
      -- ensure it ends with a newline
      if sub(value, -1) ~= "\n" then value = value .. "\n" end
      for line in gmatch(value, "([^\r\n]-)\n") do
        insert(output, format("%s  %s%s\n",
          format_get_indent(indent),
          prefix, line))
      end
    end
  end

  return concat(output)
end

---This function is deprecated.
--
-- Please use structured NSE output instead: https://nmap.org/book/nse-api.html#nse-structured-output
--
-- Takes a table of output on the commandline and formats it for display to the
-- user.
--
-- This is basically done by converting an array of nested tables into a
-- string. In addition to numbered array elements, each table can have a 'name'
-- and a 'warning' value. The 'name' will be displayed above the table, and
-- 'warning' will be displayed, with a 'WARNING' tag, if and only if debugging
-- is enabled.
--
-- Here's an example of a table:
-- <code>
--   local domains = {}
--   domains['name'] = "DOMAINS"
--   table.insert(domains, 'Domain 1')
--   table.insert(domains, 'Domain 2')
--
--   local names = {}
--   names['name'] = "NAMES"
--   names['warning'] = "Not all names could be determined!"
--   table.insert(names, "Name 1")
--
--   local response = {}
--   table.insert(response, "Apple pie")
--   table.insert(response, domains)
--   table.insert(response, names)
--
--   return stdnse.format_output(true, response)
-- </code>
--
-- With debugging enabled, this is the output:
-- <code>
--   Host script results:
--   |  smb-enum-domains:
--   |    Apple pie
--   |    DOMAINS
--   |      Domain 1
--   |      Domain 2
--   |    NAMES (WARNING: Not all names could be determined!)
--   |_     Name 1
-- </code>
--
--@param status A boolean value dictating whether or not the script succeeded.
--              If status is false, and debugging is enabled, 'ERROR' is prepended
--              to every line. If status is false and debugging is disabled, no output
--              occurs.
--@param data   The table of output.
--@param indent Used for indentation on recursive calls; should generally be set to
--              nil when calling from a script.
-- @return <code>nil</code>, if <code>data</code> is empty, otherwise a
-- multiline string.
function format_output(status, data, indent)
  -- If data is nil, die with an error (I keep doing that by accident)
  assert(data, "No data was passed to format_output()")

  -- Don't bother if we don't have any data
  if (#data == 0) then
    return nil
  end

  local result = format_output_sub(status, data, indent)

  -- Check for an empty result
  if(result == nil or #result == "" or result == "\n" or result == "\n") then
    return nil
  end

  return result
end

-- Get the value of a script argument, or nil if the script argument was not
-- given. This works also for arguments given as top-level array values, like
-- --script-args=unsafe; for these it returns the value 1.
local function arg_value(argname)
  -- First look for the literal script-arg name
  -- as a key/value pair
  if nmap.registry.args[argname] then
    return nmap.registry.args[argname]
  end
  -- and alone, as a boolean flag
  for _, v in ipairs(nmap.registry.args) do
    if v == argname then
      return 1
    end
  end

  -- if scriptname.arg is not there, check "arg"
  local shortname = match(argname, "%.([^.]*)$")
  if shortname then
    -- as a key/value pair
    if nmap.registry.args[shortname] then
      return nmap.registry.args[shortname]
    end
    -- and alone, as a boolean flag
    for _, v in ipairs(nmap.registry.args) do
      if v == shortname then
        return 1
      end
    end
  end
  return nil
end

--- Parses the script arguments passed to the --script-args option.
--
-- @usage
-- --script-args 'script.arg1=value,script.arg3,script-x.arg=value'
-- local arg1, arg2, arg3 = get_script_args('script.arg1','script.arg2','script.arg3')
--      => arg1 = "value"
--      => arg2 = nil
--      => arg3 = 1
--
-- --script-args 'displayall,unsafe,script-x.arg=value,script-y.arg=value'
-- local displayall, unsafe = get_script_args('displayall','unsafe')
--      => displayall = 1
--      => unsafe     = 1
--
-- --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2}'
-- local mode, domains = get_script_args('dns-cache-snoop.mode',
--                                       'dns-cache-snoop.domains')
--      => mode    = "timed"
--      => domains = {"host1","host2"}
--
-- @param Arguments  Script arguments to check.
-- @return Arguments values.
function get_script_args (...)
  local args = {}

  for i, set in ipairs({...}) do
    if type(set) == "string" then
      set = {set}
    end
    for _, test in ipairs(set) do
      local v = arg_value(test)
      if v then
        args[i] = v
        break
      end
    end
  end

  return unpack(args, 1, select("#", ...))
end

---Get the best possible hostname for the given host. This can be the target as given on
-- the commandline, the reverse dns name, or simply the ip address.
--@param host The host table (or a string that'll simply be returned).
--@return The best possible hostname, as a string.
function get_hostname(host)
  if type(host) == "table" then
    return host.targetname or ( host.name ~= '' and host.name ) or host.ip
  else
    return host
  end
end

---Retrieve an item from the registry, checking if each sub-key exists. If any key doesn't
-- exist, return nil.
function registry_get(subkeys)
  local registry = nmap.registry
  local i = 1

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      return nil
    end

    registry = registry[subkeys[i]]

    i = i + 1
  end

  return registry
end

--Check if the given element exists in the registry. If 'key' is nil, it isn't checked.
function registry_exists(subkeys, key, value)
  local subkey = registry_get(subkeys)

  if(not(subkey)) then
    return false
  end

  for k, v in pairs(subkey) do
    if((key == nil or key == k) and (v == value)) then -- TODO: if 'value' is a table, this fails
      return true
    end
  end

  return false
end

---Add an item to an array in the registry, creating all sub-keys if necessary.
--
-- For example, calling:
-- <code>registry_add_array({'192.168.1.100', 'www', '80', 'pages'}, 'index.html')</code>
-- Will create nmap.registry['192.168.1.100'] as a table, if necessary, then add a table
-- under the 'www' key, and so on. 'pages', finally, is treated as an array and the value
-- given is added to the end.
function registry_add_array(subkeys, value, allow_duplicates)
  local registry = nmap.registry
  local i = 1

  -- Unless the user wants duplicates, make sure there aren't any
  if(allow_duplicates ~= true) then
    if(registry_exists(subkeys, nil, value)) then
      return
    end
  end

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      registry[subkeys[i]] = {}
    end
    registry = registry[subkeys[i]]
    i = i + 1
  end

  -- Make sure the value isn't already in the table
  for _, v in pairs(registry) do
    if(v == value) then
      return
    end
  end
  insert(registry, value)
end

---Similar to <code>registry_add_array</code>, except instead of adding a value to the
-- end of an array, it adds a key:value pair to the table.
function registry_add_table(subkeys, key, value, allow_duplicates)
  local registry = nmap.registry
  local i = 1

  -- Unless the user wants duplicates, make sure there aren't any
  if(allow_duplicates ~= true) then
    if(registry_exists(subkeys, key, value)) then
      return
    end
  end

  while(subkeys[i]) do
    if(not(registry[subkeys[i]])) then
      registry[subkeys[i]] = {}
    end
    registry = registry[subkeys[i]]
    i = i + 1
  end

  registry[key] = value
end


--- This function allows you to create worker threads that may perform
-- network tasks in parallel with your script thread.
--
-- Any network task (e.g. <code>socket:connect(...)</code>) will cause the
-- running thread to yield to NSE. This allows network tasks to appear to be
-- blocking while being able to run multiple network tasks at once.
-- While this is useful for running multiple separate scripts, it is
-- unfortunately difficult for a script itself to perform network tasks in
-- parallel. In order to allow scripts to also have network tasks running in
-- parallel, we provide this function, <code>stdnse.new_thread</code>, to
-- create a new thread that can perform its own network related tasks
-- in parallel with the script.
--
-- The script launches the worker thread by calling the <code>new_thread</code>
-- function with the parameters:
-- * The main Lua function for the script to execute, similar to the script action function.
-- * The variable number of arguments to be passed to the worker's main function.
--
-- The <code>stdnse.new_thread</code> function will return two results:
-- * The worker thread's base (main) coroutine (useful for tracking status).
-- * A status query function (described below).
--
-- The status query function shall return two values:
-- * The result of coroutine.status using the worker thread base coroutine.
-- * The error object thrown that ended the worker thread or <code>nil</code> if no error was thrown. This is typically a string, like most Lua errors.
--
-- Note that NSE discards all return values of the worker's main function. You
-- must use function parameters, upvalues or environments to communicate
-- results.
--
-- You should use the condition variable (<code>nmap.condvar</code>)
-- and mutex (<code>nmap.mutex</code>) facilities to coordinate with your
-- worker threads. Keep in mind that Nmap is single threaded so there are
-- no (memory) issues in synchronization to worry about; however, there
-- is resource contention. Your resources are usually network
-- bandwidth, network sockets, etc. Condition variables are also useful if the
-- work for any single thread is dynamic. For example, a web server spider
-- script with a pool of workers will initially have a single root html
-- document. Following the retrieval of the root document, the set of
-- resources to be retrieved (the worker's work) will become very large
-- (an html document adds many new hyperlinks (resources) to fetch).
--@name new_thread
--@class function
--@param main The main function of the worker thread.
--@param ... The arguments passed to the main worker thread.
--@return co The base coroutine of the worker thread.
--@return info A query function used to obtain status information of the worker.
--@usage
--local requests = {"/", "/index.html", --[[ long list of objects ]]}
--
--function thread_main (host, port, responses, ...)
--  local condvar = nmap.condvar(responses);
--  local what = {n = select("#", ...), ...};
--  local allReqs = nil;
--  for i = 1, what.n do
--    allReqs = http.pGet(host, port, what[i], nil, nil, allReqs);
--  end
--  local p = assert(http.pipeline(host, port, allReqs));
--  for i, response in ipairs(p) do responses[#responses+1] = response end
--  condvar "signal";
--end
--
--function many_requests (host, port)
--  local threads = {};
--  local responses = {};
--  local condvar = nmap.condvar(responses);
--  local i = 1;
--  repeat
--    local j = math.min(i+10, #requests);
--    local co = stdnse.new_thread(thread_main, host, port, responses,
--        table.unpack(requests, i, j));
--    threads[co] = true;
--    i = j+1;
--  until i > #requests;
--  repeat
--    condvar "wait";
--    for thread in pairs(threads) do
--      if coroutine.status(thread) == "dead" then threads[thread] = nil end
--    end
--  until next(threads) == nil;
--  return responses;
--end
do end -- no function here, see nse_main.lua

--- Returns the base coroutine of the running script.
--
-- A script may be resuming multiple coroutines to facilitate its own
-- collaborative multithreading design. Because there is a "root" or "base"
-- coroutine that lets us determine whether the script is still active
-- (that is, the script did not end, possibly due to an error), we provide
-- this <code>stdnse.base</code> function that will retrieve the base
-- coroutine of the script. This base coroutine is the coroutine that runs
-- the action function.
--
-- The base coroutine is useful for many reasons but here are some common
-- uses:
-- * We want to attribute the ownership of an object (perhaps a network socket) to a script.
-- * We want to identify if the script is still alive.
--@name base
--@class function
--@return coroutine Returns the base coroutine of the running script.
do end -- no function here, see nse_main.lua

--- The Lua Require Function with errors silenced.
--
-- See the Lua manual for description of the require function. This modified
-- version allows the script to quietly fail at loading if a required
-- library does not exist.
--
--@name silent_require
--@class function
--@usage stdnse.silent_require "openssl"
do end -- no function here, see nse_main.lua


--- Module function that mimics some behavior of Lua 5.1 module function.
--
-- This convenience function returns a module environment to set the _ENV
-- upvalue. The _NAME, _PACKAGE, and _M fields are set as in the Lua 5.1
-- version of this function. Each option function (e.g. stdnse.seeall)
-- passed is run with the new environment, in order.
--
-- @see stdnse.seeall
-- @see strict
-- @usage
--   _ENV = stdnse.module(name, stdnse.seeall, require "strict");
-- @param name The module name.
-- @param ... Option functions which modify the environment of the module.
function module (name, ...)
  local env = {};
  env._NAME = name;
  env._PACKAGE = match(name, "(.+)%.[^.]+$");
  env._M = env;
  local mods = pack(...);
  for i = 1, mods.n do
    mods[i](env);
  end
  return env;
end

--- Change environment to load global variables.
--
-- Option function for use with stdnse.module. It is the same
-- as package.seeall from Lua 5.1.
--
-- @see stdnse.module
-- @usage
--  _ENV = stdnse.module(name, stdnse.seeall);
-- @param env Environment to change.
function seeall (env)
  local m = getmetatable(env) or {};
  m.__index = _G;
  setmetatable(env, m);
end

--- Return a table that keeps elements in order of insertion.
--
-- The pairs function, called on a table returned by this function, will yield
-- elements in the order they were inserted. This function is meant to be used
-- to construct output tables returned by scripts.
--
-- Reinserting a key that is already in the table does not change its position
-- in the order. However, removing a key by assigning to <code>nil</code> and
-- then doing another assignment will move the key to the end of the order.
--
-- @return An ordered table.
function output_table ()
  local t = {}
  local order = {}
  local function iterator ()
    for i, key in ipairs(order) do
      coroutine.yield(key, t[key])
    end
  end
  local mt = {
    __newindex = function (_, k, v)
      if t[k] == nil and v ~= nil then
        -- New key?
        insert(order, k)
      elseif v == nil then
        -- Deleting an existing key?
        for i, key in ipairs(order) do
          if key == k then
            remove(order, i)
            break
          end
        end
      end
      rawset(t, k, v)
    end,
    __index = t,
    __pairs = function (_)
      return coroutine.wrap(iterator)
    end,
    __call = function (_) -- hack to mean "not_empty?"
      return not not next(order)
    end,
    __len = function (_)
      return #order
    end
  }
  return setmetatable({}, mt)
end

--- A pretty printer for Lua objects.
--
-- Takes an object (usually a table) and prints it using the
-- printer function. The printer function takes a sole string
-- argument and will be called repeatedly.
--
-- @param obj The object to pretty print.
-- @param printer The printer function.
function pretty_printer (obj, printer)
  if printer == nil then printer = print end

  local function aux (obj, spacing)
    local t = type(obj)
    if t == "table" then
      printer "{\n"
      for k, v in pairs(obj) do
        local spacing = spacing.."\t"
        printer(spacing)
        printer "["
        aux(k, spacing)
        printer "] = "
        aux(v, spacing)
        printer ",\n"
      end
      printer(spacing.."}")
    elseif t == "string" then
      printer(format("%q", obj))
    else
      printer(tostring(obj))
    end
  end

  return aux(obj, "")
end

--- Returns a conservative timeout for a host
--
-- If the host parameter is a NSE host table with a <code>times.timeout</code>
-- attribute, then the return value is the host timeout scaled according to the
-- max_timeout. The scaling factor is defined by a linear formula such that
-- (max_timeout=8000, scale=2) and (max_timeout=1000, scale=1)
--
-- @param host The host object to base the timeout on. If this is anything but
--             a host table, the max_timeout is returned.
-- @param max_timeout The maximum timeout in milliseconds. This is the default
--                    timeout used if there is no host.times.timeout. Default: 8000
-- @param min_timeout The minimum timeout in milliseconds that will be
--                    returned. Default: 1000
-- @return The timeout in milliseconds, suitable for passing to set_timeout
-- @usage
-- assert(host.times.timeout == 1.3)
--  assert(get_timeout() == 8000)
--  assert(get_timeout(nil, 5000) == 5000)
--  assert(get_timeout(host) == 2600)
--  assert(get_timeout(host, 10000, 3000) == 3000)
function get_timeout(host, max_timeout, min_timeout)
  max_timeout = max_timeout or 8000
  local t = type(host) == "table" and host.times and host.times.timeout
  if not t then
    return max_timeout
  end
  t = t * (max_timeout + 6000) / 7
  min_timeout = min_timeout or 1000
  if t < min_timeout then
    return min_timeout
  elseif t > max_timeout then
    return max_timeout
  end
  return t
end

return _ENV;
