--- Helper functions for NSE script output
--
-- These functions are useful for ensuring output is consistently ordered
-- between scans and following conventions for output formatting.
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name outlib

local tableaux = require "tableaux"
local keys = tableaux.keys

local coroutine = require "coroutine"
local wrap = coroutine.wrap
local yield = coroutine.yield

local table = require "table"
local sort = table.sort
local concat = table.concat

local getmetatable = getmetatable
local setmetatable = setmetatable
local ipairs = ipairs

local _ENV = {}

--- Create a table that yields elements sorted by key when iterated over with pairs()
--
-- The returned table is like a sorted view of the original table; it should be
-- treated as read-only, and any new data should be added to the original table
-- instead.
--@param  t    The table whose data should be used
--@return out  A table that can be passed to pairs() to get sorted results
function sorted_by_key(t)
  local out = {}
  setmetatable(out, {
    __pairs = function(_)
      local order = keys(t)
      sort(order)
      return wrap(function()
        for i,k in ipairs(order) do
          yield(k, t[k])
        end
      end)
    end
  })
  return out
end

local commasep = {
  __tostring = function (t)
    return concat(t, ", ")
  end
}

--- Comma-separated list output
--
-- This adds a <code>__tostring</code> metamethod to a list (integer-indexed
-- table) so that it will be formatted as a comma-separated list when converted
-- to a string.
-- @param t The table to format
-- @param sep (Optional) list separator character, default: ", "
function list_sep(t, sep)
  -- Reuse closures and metatables as much as possible
  local oldmt = getmetatable(t)
  local newmt = sep and {
    __tostring = function(tt)
      return concat(tt, sep)
  end} or commasep
  -- Avoid clobbering old metatable or our static commasep table
  if oldmt and oldmt ~= commasep then
    oldmt.__tostring = newmt.__tostring
  else
    setmetatable(t, newmt)
  end
end

return _ENV
