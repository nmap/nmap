--- Standard Nmap Scripting Engine functions.
--
-- This module contains various handy functions that are too small to justify
-- modules of their own.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local assert = assert;
local tonumber = tonumber;
local error = error;
local concat = table.concat;
local nmap = require"nmap";
local max = math.max
local ceil = math.ceil
local type = type

local EMPTY = {}; -- Empty constant table

module(... or "stdnse");

--- Prints a formatted debug message if the current verbosity level is greater
-- than or equal to a given level.
-- 
-- This is a convenience wrapper around
-- <code>nmap.print_debug_unformatted()</code>. The first optional numeric
-- argument, <code>verbosity</code>, is used as the verbosity level necessary
-- to print the message (it defaults to 1 if omitted). All remaining arguments
-- are processed with Lua's <code>string.format()</code> function.
-- @param level Optional verbosity level.
-- @param fmt Format string.
-- @param ... Arguments to format.
print_debug = function(level, fmt, ...)
  local verbosity = tonumber(level);
  if verbosity then
    nmap.print_debug_unformatted(verbosity, fmt:format(...));
  else
    nmap.print_debug_unformatted(1, level:format(fmt, ...));
  end
end

--- Join a list of strings with a separator string.
-- 
-- This is Lua's <code>table.concat()</code> function with the parameters
-- swapped for coherence.
-- @usage
-- strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
-- --> "Anna, Bob, Charlie, Dolores"
-- @param delimiter String to delimit each element of the list.
-- @param list Array of strings to concatenate.
-- @return Concatenated string.
function strjoin(delimiter, list)
  return concat(list, delimiter);
end

--- Split a string at a given delimiter, which may be a pattern.
-- @usage
-- strsplit(",%s*", "Anna, Bob, Charlie, Dolores")
-- --> { "Anna", "Bob", "Charlie", "Dolores" }
-- @param pattern Pattern that separates the desired strings.
-- @param text String to split.
-- @return Array of substrings without the separating pattern.
function strsplit(pattern, text)
  local list, pos = {}, 1;

  assert(pattern ~= "", "delimiter matches empty string!");

  while true do
    local first, last, match = text:find(pattern, pos);
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
-- @return Error message, as with <code>receive_lines()</code>.
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

--- Converts the given number, n, to a string in a binary number format (12
-- becomes "1100").
-- @param n Number to convert.
-- @return String in binary format.
  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

--- Converts the given number, n, to a string in an octal number format (12
-- becomes "14").
-- @param n Number to convert.
-- @return String in octal format.
function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

--- Encode a string or number in hexadecimal (12 becomes "c", "AB" becomes
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
-- @param options Table specifiying formatting options.
-- @return String in hexadecimal format.
function tohex( s, options ) 
  options = options or EMPTY
  local separator = options.separator
  local hex

  if type( s ) == "number" then
    hex = ("%x"):format(s)
  elseif type( s ) == 'string' then
    hex = ("%02x"):rep(#s):format(s:byte(1,#s))
  else
    error( "Type not supported in tohex(): " .. type(s), 2 )
  end

  -- format hex if we got a separator
  if separator then
    local group = options.group or 2
    local fmt_table = {}
    -- split hex in group-size chunks
    for i=#hex,1,-group do
      -- table index must be consecutive otherwise table.concat won't work
      fmt_table[ceil(i/group)] = hex:sub(max(i-group+1,1),i)
    end

    hex = concat( fmt_table, separator )
  end

  return hex
end

