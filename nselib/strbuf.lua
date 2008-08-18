--- String Buffer Facilities
--@copyright See nmaps COPYING for license

-- DEPENDENCIES --

local getmetatable = getmetatable;
local setmetatable = setmetatable;
local type = type;
local error = error;
local ipairs = ipairs;
local pairs = pairs;
local concat = table.concat;


module(... or "strbuf");

-- String buffer functions. Concatenation is not efficient in 
-- lua as strings are immutable. If a large amount of '..' sequential
-- operations are needed a string buffer should be used instead
-- e.g. for i = 1, 10 do s = s..i end

--[[
	local buf = strbuf.new()
	-- from here buf may be used like a string for concatenation operations
	-- (the lefthand-operand has to be a strbuf, the righthand-operand may be 
	-- a string or a strbuf)
	-- alternativly you can assign a value (which will become the first string
	-- inside the buffer) with new
	local buf2 = strbuf.new('hello')
	buf = buf .. 'string'
	buf = buf .. 'data'
	print(buf)                   -- default seperator is a new line
	print(strbuf.dump(buf))      -- no seperator
	print(strbuf.dump(buf, ' ')) -- seperated by spaces
	strbuf.clear(buf)
--]]

--- Dumps the string buffer as a string.
--@name dump
--@class function
--@param sbuf String buffer to dump.
--@param delimiter String to separate the buffer's contents.
--@return Concatenated string result.
dump = concat;

--- Appends the string s to the buffer, sbuf.
--@param sbuf String buffer.
--@param s String to append.
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

--- Determines if the two buffers are equal. Two buffers are equal
-- if they are the same or if they have equivalent contents.
--@param sbuf1 String buffer one.
--@param sbuf2 String buffer two.
--@return boolean true if equal, false otherwise.
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

--- Clears the string buffer.
--@param sbuf String buffer.
function clear(sbuf)
  for k in pairs(sbuf) do
    sbuf[k] = nil;
  end
end

--- Returns the result of the buffer as a string. The delimiter used
-- is a newline.
--@param sbuf String buffer.
--@return String made from concatenating the buffer.
function tostring(sbuf)
  return concat(sbuf, "\n");
end

local mt = {
  __concat = concatbuf,
  __tostring = tostring,
  __eq = eqbuf,
  __index = _M,
};

--- Create a new string buffer. The equals and tostring operators for String
-- buffers are overloaded to be strbuf.eqbuf and strbuf.tostring respectively.
-- All functions in strbuf can be accessed by a String buffer using the self
-- calling mechanism in Lua (e.g. strbuf:dump(...)).
--@param ... Strings to add to the buffer initially.
--@return String buffer.
function new(...)
  return setmetatable({...}, mt);
end
