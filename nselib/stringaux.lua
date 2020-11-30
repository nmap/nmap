--- Auxiliary functions for string manipulation
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name stringaux

local assert = assert
local type = type

local string = require "string"
local byte = string.byte
local find = string.find
local match = string.match
local sub = string.sub
local gsub = string.gsub
local format = string.format
local lower = string.lower
local upper = string.upper

local table = require "table"
local concat = table.concat

local _ENV = {}

--- Join a list of strings with a separator string.
--
-- This is Lua's <code>table.concat</code> function with the parameters
-- swapped for coherence.
-- @usage
-- stringaux.strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
-- --> "Anna, Bob, Charlie, Dolores"
-- @param delimiter String to delimit each element of the list.
-- @param list Array of strings to concatenate.
-- @return Concatenated string.
function strjoin(delimiter, list)
  assert(type(delimiter) == "string" or type(delimiter) == nil, "delimiter is of the wrong type! (did you get the parameters backward?)")

  return concat(list, delimiter);
end

--- Split a string at a given delimiter, which may be a pattern.
--
-- If you want to loop over the resulting values, consider using string.gmatch instead.
-- @usage
-- stringaux.strsplit(",%s*", "Anna, Bob, Charlie, Dolores")
-- --> { "Anna", "Bob", "Charlie", "Dolores" }
-- @param pattern Pattern that separates the desired strings.
-- @param text String to split.
-- @return Array of substrings without the separating pattern.
-- @see string.gmatch
function strsplit(pattern, text)
  local list, pos = {}, 1;

  assert(pattern ~= "", "delimiter matches empty string!");

  while true do
    local first, last = find(text, pattern, pos);
    if first then -- found?
      list[#list+1] = sub(text, pos, first-1);
      pos = last+1;
    else
      list[#list+1] = sub(text, pos);
      break;
    end
  end
  return list;
end

-- This pattern must match the percent sign '%' since it is used in
-- escaping.
local FILESYSTEM_UNSAFE = "[^a-zA-Z0-9._-]"
local function _escape_helper (c)
  return format("%%%02x", byte(c))
end
---
-- Escape a string to remove bytes and strings that may have meaning to
-- a filesystem, such as slashes.
--
-- All bytes are escaped, except for:
-- * alphabetic <code>a</code>-<code>z</code> and <code>A</code>-<code>Z</code>
-- * digits 0-9
-- * <code>.</code> <code>_</code> <code>-</code>
-- In addition, the strings <code>"."</code> and <code>".."</code> have
-- their characters escaped.
--
-- Bytes are escaped by a percent sign followed by the two-digit
-- hexadecimal representation of the byte value.
-- * <code>filename_escape("filename.ext") --> "filename.ext"</code>
-- * <code>filename_escape("input/output") --> "input%2foutput"</code>
-- * <code>filename_escape(".") --> "%2e"</code>
-- * <code>filename_escape("..") --> "%2e%2e"</code>
-- This escaping is somewhat like that of JavaScript
-- <code>encodeURIComponent</code>, except that fewer bytes are
-- whitelisted, and it works on bytes, not Unicode characters or UTF-16
-- code points.
function filename_escape(s)
  if s == "." then
    return "%2e"
  elseif s == ".." then
    return "%2e%2e"
  else
    return (gsub(s, FILESYSTEM_UNSAFE, _escape_helper))
  end
end

--- Returns the case insensitive pattern of given parameter
--
-- Useful while doing case insensitive pattern match using string library.
-- https://stackoverflow.com/questions/11401890/case-insensitive-lua-pattern-matching/11402486#11402486
--
-- @usage stringaux.ipattern("user")
-- --> "[uU][sS][eE][rR]"
-- @param pattern The string
-- @return A case insensitive patterned string
function ipattern(pattern)
  local in_brackets = false
  -- Find an optional '%' (group 2) followed by any character (group 3)
  local p = gsub(pattern, "(%%?)(.)", function(percent, letter)
    if percent ~= "" then
      -- It's a %-escape, return as-is
      return nil
    elseif not match(letter, "%a") then
      -- It's not alpha. Update bracket status and return as-is
      if letter == "[" then
        in_brackets = true
      elseif letter == "]" then
        in_brackets = false
      end
      return nil
    elseif not in_brackets then
      -- Else, return a case-insensitive character class of the matched letter
      return format("[%s%s]", lower(letter), upper(letter))
    end
  end)

  return p
end

return _ENV
