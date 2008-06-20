-- See nmaps COPYING for licence

local assert = assert;
local tonumber = tonumber;
local concat = table.concat;
local nmap = require"nmap";
local print = print

module(... or "stdnse");

print_debug = function(level, fmt, ...)
  local verbosity = tonumber(level);
  if verbosity then
    nmap.print_debug_unformatted(verbosity, fmt:format(...));
  else
    nmap.print_debug_unformatted(1, level:format(...));
  end
end

-- Concat the contents of the parameter list,
-- separated by the string delimiter (just like in perl)
-- example: strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
function strjoin(delimiter, list)
  return concat(list, delimiter);
end

-- Split text into a list consisting of the strings in text,
-- separated by strings matching delimiter (which may be a pattern). 
-- example: strsplit(",%s*", "Anna, Bob, Charlie,Dolores")
function strsplit(delimiter, text)
  local list, pos = {}, 1;

  assert(delimiter ~= "", "delimiter matches empty string!");

  while true do
    local first, last, match = text:find(delimiter, pos);
    if first then -- found?
      list[#list+1] = text:sub(pos, first-1);
      pos = last+1;
    else
      list[#list+1] = text:sub(pos);
      break;
    end
  end
  return list;
end

-- Generic buffer implementation using lexical closures
--
-- Pass make_buffer a socket and a separator lua pattern [1].
--
-- Returns a function bound to your provided socket with behaviour identical
-- to receive_lines() except it will return AT LEAST ONE [2] and AT MOST ONE
-- "line" at a time.
--
-- [1] Use the pattern "\r?\n" for regular newlines
-- [2] Except where there is trailing "left over" data not terminated by a
--     pattern (in which case you get the data anyways)
-- [3] The data is returned WITHOUT the pattern/newline on the end.
-- [4] Empty "lines" are returned as "". With the pattern in [1] you will
--     receive a "" for each newline in the stream.
-- [5] Errors/EOFs are delayed until all "lines" have been processed.
--
-- -Doug, June, 2007

function make_buffer(socket, sep)
  local point, left, buffer, done, msg = 1, "";
  local function self()
    if done then
      return nil, msg; -- must be nil for stdnse.lines (below)
    elseif not buffer then
      local status, str = socket:receive_lines(1);
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
      local i, j = buffer:find(sep, point);
      if i then
        local ret = buffer:sub(point, i-1);
        point = j + 1;
        return ret;
      else
        point, left, buffer = 1, buffer:sub(point), nil;
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

  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

function tohex(n)
  assert(tonumber(n), "number expected");
  return ("%x"):format(n);
end
