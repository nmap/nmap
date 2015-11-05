---
-- Debugging functions for Nmap scripts.
--
-- This module contains various handy functions for debugging. These should
-- never be used for actual results, only during testing.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local coroutine = require "coroutine"
local debug = require "debug"
local io = require "io"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("nsedebug", stdnse.seeall)

local EMPTY = {}; -- Empty constant table

---
-- Converts an arbitrary data type into a string. Will recursively convert
-- tables. This can be very useful for debugging.
--
--@param data   The data to convert.
--@param indent (optional) The number of times to indent the line. Default
--              is 0.
--@return A string representation of a data, will be one or more full lines.
function tostr(data, indent)
  local str

  if(indent == nil) then
    indent = 0
  end

  -- Check the type
  local typ = type(data)
  if(typ == "nil" or typ == "number" or typ == "boolean" or typ == "function" or typ == "thread" or typ == "userdata") then
    str = {(" "):rep(indent), tostring(data), "\n"}
  elseif(type(data) == "string") then
    str = {(" "):rep(indent), string.format("%q", data), "\n"}
  elseif(type(data) == "table") then
    local i, v
    str = {}
    for i, v in pairs(data) do
      -- Check for a table in a table
      str[#str+1] = (" "):rep(indent)
      str[#str+1] = tostring(i)
      if(type(v) == "table") then
        str[#str+1] = ":\n"
        str[#str+1] = tostr(v, indent + 2)
      else
        str[#str+1] = ": "
        str[#str+1] = tostr(v, 0)
      end
    end
  else
    stdnse.debug1("Error: unknown data type: %s", type(data))
  end

  return table.concat(str)
end

--- Print out a string in hex, for debugging.
--
--@param str The data to print in hex.
function print_hex(str)

  -- Prints out the full lines
  for line=1, #str/16, 1 do
    io.write(string.format("%08x ", (line - 1) * 16))

    -- Loop through the string, printing the hex
    for char=1, 16, 1 do
      local ch = string.byte(str, ((line - 1) * 16) + char)
      io.write(string.format("%02x ", ch))
    end

    io.write("   ")

    -- Loop through the string again, this time the ascii
    for char=1, 16, 1 do
      local ch = string.byte(str, ((line - 1) * 16) + char)
      if ch < 0x20 or ch > 0x7f then
        ch = string.byte(".", 1)
      end
      io.write(string.format("%c", ch))
    end

    io.write("\n")
  end

  -- Prints out the final, partial line
  if (#str % 16 ~= 0) then
    local line = math.floor((#str/16)) + 1
    io.write(string.format("%08x ", (line - 1) * 16))

    for char=1, #str % 16, 1 do
      local ch = string.byte(str, ((line - 1) * 16) + char)
      io.write(string.format("%02x ", ch))
    end
    io.write(string.rep("   ", 16 - (#str % 16)));
    io.write("   ")

    for char=1, #str % 16, 1 do
      local ch = string.byte(str, ((line - 1) * 16) + char)
      if ch < 0x20 or ch > 0x7f then
        ch = string.byte(".", 1)
      end
      io.write(string.format("%c", ch))
    end

    io.write("\n")
  end

  -- Print out the length
  io.write(string.format("         Length: %d [0x%x]\n", #str, #str))

end

---Print out a stacktrace. The stacktrace will naturally include this function call.
function print_stack()
  local thread = coroutine.running()
  local trace = debug.traceback(thread);
  if trace ~= "stack traceback:" then
    print(thread, "\n", trace, "\n");
  end
end



return _ENV;
