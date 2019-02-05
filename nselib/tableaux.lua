--- Auxiliary functions for table manipulation
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name tableaux

local next = next
local pairs = pairs
local ipairs = ipairs
local type = type
local _ENV = {}

local tcopy_local
--- Recursively copy a table.
--
-- Uses simple assignment to copy keys and values from a table, recursing into
-- subtables as necessary.
-- @param t the table to copy
-- @return a deep copy of the table
function tcopy (t)
  local tc = {};
  for k,v in pairs(t) do
    if type(v) == "table" then
      tc[k] = tcopy_local(v);
    else
      tc[k] = v;
    end
  end
  return tc;
end
tcopy_local = tcopy

--- Copy one level of a table.
--
-- Iterates over the keys of a table and copies their values into a new table.
-- If any values are tables, they are copied by reference only, and modifying
-- the copy will modify the original table value as well.
-- @param t the table to copy
-- @return a shallow copy of the table
function shallow_tcopy(t)
  local k = next(t)
  local out = {}
  while k do
    out[k] = t[k]
    k = next(t, k)
  end
  return out
end

--- Invert a one-to-one mapping
-- @param t the table to invert
-- @return an inverted mapping
function invert(t)
  local out = {}
  for k, v in pairs(t) do
    out[v] = k
  end
  return out
end

--- Check for the presence of a value in a table
--@param t the table to search into
--@param item the searched value
--@array (optional) If true, then use ipairs to only search the array indices of the table.
--@return Boolean true if the item was found, false if not
--@return The index or key where the value was found, or nil
function contains(t, item, array)
  local iter = array and ipairs or pairs
  for k, val in iter(t) do
    if val == item then
      return true, k
    end
  end
  return false, nil
end

--- Returns the keys of a table as an array
-- @param t The table
-- @return A table of keys
function keys(t)
  local ret = {}
  local k, v = next(t)
  while k ~= nil do
    ret[#ret+1] = k
    k, v = next(t, k)
  end
  return ret
end

return _ENV
