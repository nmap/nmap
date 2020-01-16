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

return _ENV
