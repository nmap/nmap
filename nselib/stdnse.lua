--- Standard Nmap Engine functions.
--@copyright See nmaps COPYING for licence

local assert = assert;
local tonumber = tonumber;
local concat = table.concat;
local nmap = require"nmap";

module(... or "stdnse");

--- Prints debug information according with verbosity <i>level</i>
-- formatted using Lua's standard string.format function.
--@param level Optional argument for verbosity.
--@param fmt Format string according to string.format specifiers.
--@param ... Arguments to format.
--@see string.format
print_debug = function(level, fmt, ...)
  local verbosity = tonumber(level);
  if verbosity then
    nmap.print_debug_unformatted(verbosity, fmt:format(...));
  else
    nmap.print_debug_unformatted(1, level:format(fmt, ...));
  end
end

--- Concat the contents of the parameter list. Each string is
-- separated by the string delimiter (just like in perl).
-- Example: strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
-- --> "Anna, Bob, Charlie, Dolores"
--@param delimiter String to delimit each element of the list.
--@param list Array of strings to concatenate.
--@return Concatenated string.
function strjoin(delimiter, list)
  return concat(list, delimiter);
end

--- Split text into a list consisting of the strings in text,
-- separated by strings matching delimiter (which may be a pattern). 
-- example: strsplit(",%s*", "Anna, Bob, Charlie, Dolores")
--@param delimiter String which delimits the split strings.
--@param text String to split.
--@return List of strings.
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

--- This function operates on a socket attempting to read data. It separates
-- the data by sep and, for each invocation, returns a piece of the
-- separated data. Typically this is used to iterate over the lines of
-- data received from a socket (sep = "\r?\n"). The returned string does
-- not include the separator. It will return the final data even if it is
-- not followed by the separator. Once an error or EOF is reached, it
-- returns nil, msg. msg is what is returned by nmap.receive_lines(). 
-- @param socket Socket for the buffer.
-- @param sep Separator for the buffered reads.
-- @return Data from socket reads.
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

--- Converts the given number, n, to a string in a binary number format.
--@param n Number to convert.
--@return String in binary format.
  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

--- Converts the given number, n, to a string in an octal number format.
--@param n Number to convert.
--@return String in octal format.
function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

--- Converts the given number, n, to a string in a hexidecimal number format.
--@param n Number to convert.
--@return String in hexidecimal format.
function tohex(n)
  assert(tonumber(n), "number expected");
  return ("%x"):format(n);
end
