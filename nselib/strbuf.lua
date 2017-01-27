---
-- String buffer facilities.
--
-- Lua's string operations are very flexible and offer an easy-to-use way to
-- manipulate strings. Concatenation using the <code>..</code> operator is such
-- an operation. The drawback of the built-in API however is the way it handles
-- concatenation of many string values. Since strings in Lua are immutable
-- values, each time you concatenate two strings both get copied into the
-- result string.
--
-- The <code>strbuf</code> module offers a workaround for this problem, while
-- maintaining the nice syntax. This is accomplished by overloading the
-- concatenation operator (<code>..</code>), the equality operator (<code>==</code>) and the <code>tostring</code>
-- operator. A string buffer is created by passing a string to
-- <code>strbuf.new</code>. Afterwards you can append to the string buffer,
-- or compare two string buffers for equality just as you would do with normal
-- strings.
--
-- When looking at the details there are some more restrictions/oddities: The
-- concatenation operator requires its left-hand value to be a string buffer.
-- Therefore, if you want to prepend a string to a given string buffer you have
-- to create a new string buffer out of the string you want to prepend. The
-- string buffer's <code>tostring</code> operator concatenates the strings
-- inside the buffer using newlines by default, since this appears to be the
-- separator used most often.
--
-- Example usage:
-- <code>
-- local buf = strbuf.new()
-- local buf2 = strbuf.new('hello')
-- buf = buf .. 'string'
-- buf = buf .. 'data'
-- print(buf)                   -- default separator is a newline
-- print(strbuf.dump(buf))      -- no separator
-- print(strbuf.dump(buf, ' ')) -- separated by spaces
-- strbuf.clear(buf)
-- </code>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- DEPENDENCIES --

local stdnse = require "stdnse"
local table = require "table"
local getmetatable = getmetatable;
local setmetatable = setmetatable;
local type = type;
local error = error;
local ipairs = ipairs;
local pairs = pairs;
local concat = table.concat;

_ENV = stdnse.module("strbuf", stdnse.seeall)

-- String buffer functions. Concatenation is not efficient in
-- lua as strings are immutable. If a large amount of '..' sequential
-- operations are needed a string buffer should be used instead
-- e.g. for i = 1, 10 do s = s..i end

--- Dumps the string buffer as a string.
--
-- The second parameter is used as a delimiter between the strings stored inside
-- the string buffer.
-- @name dump
-- @class function
-- @param sbuf String buffer to dump.
-- @param delimiter String to separate the buffer's contents.
-- @return Concatenated string result.
dump = concat;

--- Appends a string to a string buffer.
-- @param sbuf String buffer.
-- @param s String to append.
-- @return <code>sbuf</code>.
function concatbuf(sbuf, s)
  if type(s) == "string" then
    sbuf[#sbuf+1] = s;
  elseif getmetatable(s) == getmetatable(sbuf) then
    for _,v in ipairs(s) do
      sbuf[#sbuf+1] = v;
    end
  else
    error("bad #2 operand to strbuf concat operation", 2);
  end
  return sbuf;
end

--- Determines if the two string buffers are equal. Two buffers are equal
-- if they are the same or if they have equivalent contents.
-- @param sbuf1 String buffer one.
-- @param sbuf2 String buffer two.
-- @return True if equal, false otherwise.
function eqbuf(sbuf1, sbuf2)
  if getmetatable(sbuf1) ~= getmetatable(sbuf2) then
    error("one or more operands is not a string buffer", 2);
  elseif #sbuf1 ~= #sbuf2 then
    return false;
  else
    for i = 1, #sbuf1 do
      if sbuf1[i] ~= sbuf2[i] then
        return false;
      end
    end
    return true;
  end
end

--- Clears a string buffer.
-- @param sbuf String buffer.
function clear(sbuf)
  for k in pairs(sbuf) do
    sbuf[k] = nil;
  end
end

--- Returns the string buffer as a string. The delimiter used is a newline.
-- @param sbuf String buffer.
-- @return String made from concatenating the buffer.
function tostring(sbuf)
  return concat(sbuf, "\n");
end

local mt = {
  __concat = concatbuf,
  __tostring = tostring,
  __eq = eqbuf,
  __index = _M,
};

--- Create a new string buffer.
--
-- The optional arguments are added to the string buffer. The result of adding
-- non-strings is undefined. The <code>equals</code> and <code>tostring</code>
-- operators for string buffers are overloaded to be <code>eqbuf</code> and
-- <code>tostring</code> respectively.
-- @param ... Strings to add to the buffer initially.
-- @return String buffer.
function new(...)
  return setmetatable({...}, mt);
end

return _ENV;
