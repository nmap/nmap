local msrpc     = require "msrpc"
local shortport = require "shortport"
local string    = require "string"

description = [[
Checks for the presence of the Windows Security Center service by querying
the MSRPC Endpoint Mapper over TCP port 135.

The Security Center service is present on Windows 10 but not on Windows
Server 2019, and can be used as a heuristic when OS fingerprinting results
are inconclusive.
]]
---
-- @usage
-- nmap -p 135 --script msrpc-epm-securitycenter <target>
--
-- @output
-- | msrpc-epm-securitycenter:
-- |   Security Center service present (likely Windows 10)
--

author = "Sweekar-cmd (https://github.com/Sweekar-cmd)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

portrule = shortport.port_or_service(135, "msrpc")

action = function(host, port)
  local status, rpcstate = msrpc.start_ex(host, port)
  if not status then
    return nil
  end

  status = msrpc.bind(rpcstate,
                      msrpc.EPMAPPER_UUID,
                      msrpc.EPMAPPER_VERSION)
  if not status then
    msrpc.stop(rpcstate)
    return nil
  end

  local handle = nil
  local found = false

  repeat
    local result
    status, result = msrpc.epmapper_lookup(rpcstate, handle)
    if not status or not result then
      break
    end

    handle = result.new_handle

    if result.annotation and
       string.find(result.annotation:lower(),
                   "security center", 1, true) then
      found = true
      break
    end
  until handle == nil

  msrpc.stop(rpcstate)

  if found then
    return "Security Center service present (likely Windows 10)"
  end

  return "Security Center service not detected"
end
