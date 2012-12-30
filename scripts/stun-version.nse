local nmap = require "nmap"
local shortport = require "shortport"
local stun = require "stun"

description = [[
Sends a binding request to the server and attempts to extract version
information from the response, if the server attribute is present.
]]

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 3478/udp open  stun    Vovida.org 0.96
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}


portrule = shortport.version_port_or_service(3478, "stun", "udp")

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function(host, port)
	local helper = stun.Helper:new(host, port)
	local status = helper:connect()
	if ( not(status) ) then
		return fail("Failed to connect to server")
	end
	
	local status, result = helper:getVersion()
	if ( not(status) ) then
		return fail("Failed to retrieve external IP")
	end

	port.version.name = "stun"
	port.version.product = result
	nmap.set_port_state(host, port, "open")
	nmap.set_port_version(host, port)
end
