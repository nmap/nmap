local stdnse = require "stdnse"
local string = require "string"
local target = require "target"

description = [[
Inserts traceroute hops into the Nmap scanning queue. It only functions if Nmap's <code>--traceroute</code> option is used and the <code>newtargets</code> script argument is given.
]]

---
-- @args newtargets  If specified, adds traceroute hops onto Nmap
--                   scanning queue.
--
-- @usage
-- nmap --script targets-traceroute --script-args newtargets --traceroute target
--
-- @output
-- Host script results:
-- |_traceroute-scan-hops: successfully added 5 new targets.


-- 09/02/2010
author = "Henri Doreau"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


hostrule = function(host)
  -- print debug messages because the script relies on
  -- script arguments and traceroute results.
  if not target.ALLOW_NEW_TARGETS then
    stdnse.print_debug(3,
      "Skipping %s script, 'newtargets' script argument is missing.",
      SCRIPT_NAME)
    return false
  end
  if not host.traceroute then
    stdnse.print_debug(3,
      "Skipping %s script because traceroute results are missing.",
      SCRIPT_NAME)
    return false
  end
  return true
end

action = function(host)
  local ntargets = 0
  for _, hop in ipairs(host.traceroute) do
    -- avoid timedout hops, marked as empty entries
    -- do not add the current scanned host.ip
    if hop.ip and host.ip ~= hop.ip then
      local status, ret = target.add(hop.ip)
      if status then
        ntargets = ntargets + ret
        stdnse.print_debug(3,
            "TRACEROUTE Scan Hops: Added new target "..host.ip.." from traceroute results")
      else
        stdnse.print_debug(3, "TRACEROUTE Scan Hops: " .. ret)
      end
    end
  end

  if ntargets > 0 then
    return string.format("successfully added %d new targets.\n", ntargets)
  end
end
