---
-- Utility functions to add new discovered targets to Nmap scan queue.
--
-- The library lets scripts to add new discovered targets to Nmap scan
-- queue. Only scripts that run in the script pre-scanning phase
-- (prerule) and the script scanning phase (hostrule and portrule) are
-- able to add new targets. Post-scanning scripts (postrule) are not
-- allowed to add new targets.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @args newtargets  If specified, lets NSE scripts add new targets.
-- @args max-newtargets  Sets the number of the maximum allowed
--                       new targets. If set to 0 or less then there
--                       is no limit. The default value is 0.

local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local type      = type
local select    = select
local tonumber  = tonumber

_ENV = stdnse.module("target", stdnse.seeall)


-- This is a special variable and it is a global one, so
-- scripts can check it to see if adding targets is allowed,
-- before calling target.add() function.
-- This variable will be set to true if the script argument
-- 'newtargets' was specified.
ALLOW_NEW_TARGETS = false

local newtargets, max_newtargets = stdnse.get_script_args("newtargets",
                                        "max-newtargets")
if newtargets then
  ALLOW_NEW_TARGETS = true
end

if max_newtargets then
  max_newtargets = tonumber(max_newtargets)
else
  max_newtargets = 0
end

--- Local function to calculate max allowed new targets
local calc_max_targets = function(targets)
  if max_newtargets > 0 then
    local pushed_targets = nmap.new_targets_num()
    if pushed_targets >= max_newtargets then
      return 0
    elseif (targets + pushed_targets) > max_newtargets then
      return (max_newtargets - pushed_targets)
    end
  end
  return targets
end

--- Adds the passed arguments to the Nmap scan queue.
--
-- Only prerule, portrule and hostrule scripts can add new targets.
--
-- @param targets  A variable number of targets. Target is a
-- string that represents an IP or a Hostname. If this function
-- is called without target arguments then it will return true
-- and the number of pending targets (waiting to be scanned).
-- @usage
-- local status, err = target.add("192.168.1.1")
-- local status, err = target.add("192.168.1.1","192.168.1.2",...)
-- local status, err = target.add("scanme.nmap.org","192.168.1.1",...)
-- local status, err = target.add(table.unpack(array_of_targets))
-- local status, pending_targets = target.add()
-- @return True if it has been able to add a minimum one target, or
--         False on failures and if no targets were added. If this
--         function is called without target arguments then it will
--         return true.
-- @return Number of added targets on success, or a string error
--         message in case of failures. If this function is called
--         without target arguments then it will return the number
--         of targets that are in the queue (waiting to be scanned).
add = function (...)
  -- Force the check here, but it would be better if scripts
  -- check ALLOW_NEW_TARGETS before calling target.add()
  if not ALLOW_NEW_TARGETS then
    stdnse.debug1(
        "ERROR: to add targets run with --script-args 'newtargets'")
    return false, "to add targets run with --script-args 'newtargets'"
  end

  local new_targets = {count = select("#", ...), ...}

  -- function called without arguments
  if new_targets.count == 0 then
    return true, nmap.add_targets()
  end

  new_targets.count = calc_max_targets(new_targets.count)

  if new_targets.count == 0 then
    stdnse.debug3(
        "Warning: Maximum new targets reached, no more new targets.")
    return false, "Maximum new targets reached, no more new targets."
  end

  local hosts, err = nmap.add_targets(table.unpack(new_targets,1,new_targets.count))

  if hosts == 0 then
    stdnse.debug3("%s", err)
    return false, err
  end

  return true, hosts
end

return _ENV;
