---
-- Strict declared global library. Checks for undeclared global variables
-- during runtime execution.
--
-- This module places the <code>strict</code> function in the global
-- environment. The strict function allows a script to add runtime checking so
-- that undeclared globals cause an error to be raised. This is useful for
-- finding accidental use of globals when local was intended.
--
-- A global variable is considered "declared" if the script makes an assignment
-- to the global name (even <code>nil</code>) in the file scope.
--
-- @class module
-- @name strict
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local debug = require "debug"

local error = error;
local getmetatable = getmetatable;
local rawset = rawset;
local rawget = rawget;
local setmetatable = setmetatable;
local type = type;

local getinfo = debug.getinfo;

_ENV = {};

local function what ()
  local d = getinfo(3, "S");
  return d and d.what or "C";
end

--- The strict function.
--
-- This function adds runtime checking to the global environment for use of
-- undeclared globals. A global is 'undeclared' if not assigned in the file
-- (script) scope previously. An error will be raised on use of an undeclared
-- global.
--
-- This function should be passed last to stdnse.module in order to allow
-- other environment option functions (e.g. stdnse.seeall) to change the
-- environment first. This is important for allowing globals outside the
-- library (in _G) to be indexed.
--
-- @see stdnse.module
-- @usage
--  _ENV = stdnse.module(name, require "strict");
-- @param env The environment to modify.
local function strict (env)
  local mt = getmetatable(env) or setmetatable(env, {}) and getmetatable(env);
  local _newindex, _index = mt.__newindex, mt.__index;

  mt.__declared = {};

  function mt.__newindex (t, n, v)
    if type(_newindex) == "function" then
      _newindex(t, n, v); -- hook it
    end
    if not mt.__declared[n] then
      local w = what();
      if w ~= "main" and w ~= "C" then
        error("assign to undeclared variable '"..n.."'", 2);
      end
      mt.__declared[n] = true;
    end
    rawset(t, n, v);
  end

  function mt.__index (t, n)
    if type(_index) == "function" then
      local v = _index(t, n); -- hook it
      if v ~= nil then return v end
    elseif _index ~= nil then
      local v = _index[n];
      if v ~= nil then return v end
    end
    if not mt.__declared[n] and what() ~= "C" then
      error("variable '"..n.."' is not declared", 2);
    end
    return rawget(t, n);
  end

  return env;
end

return strict;
