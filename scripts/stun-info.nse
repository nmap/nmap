local nmap = require "nmap"
local shortport = require "shortport"
local stun = require "stun"
local stdnse = require "stdnse"

description = [[
Retrieves the external IP address of a NAT:ed host using the STUN protocol.
]]

---
-- @usage
-- nmap -sV -PN -sU -p 3478 --script stun-info <ip>
--
-- @output
-- PORT     STATE         SERVICE
-- 3478/udp open|filtered stun
-- | stun-info:
-- |_  External IP: 80.216.42.106
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(3478, "stun", "udp")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  local helper = stun.Helper:new(host, port)
  local status = helper:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, result = helper:getExternalAddress()
  if ( not(status) ) then
    return fail("Failed to retrieve external IP")
  end

  port.version.name = "stun"
  nmap.set_port_state(host, port, "open")
  nmap.set_port_version(host, port)

  if ( result ) then
    return "\n  External IP: " .. result
  end
end
