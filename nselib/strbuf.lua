-- license = "See nmaps COPYING for license"

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

dump = concat;

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

function clear(sbuf)
  for k in pairs(sbuf) do
    sbuf[k] = nil;
  end
end

function tostring(sbuf)
  return concat(sbuf, "\n");
end

local mt = {
  __concat = concatbuf,
  __tostring = tostring,
  __eq = eqbuf,
  __index = _M,
};

function new(...)
  return setmetatable({...}, mt);
end
