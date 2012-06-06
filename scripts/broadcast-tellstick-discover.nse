local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description=[[
Discovers Telldus Technologies TellStickNet devices on the LAN. The Telldus
TellStick is used to wirelessly control electric devices such as lights,
dimmers and electric outlets. For more information: http://www.telldus.com/
]]

---
-- @usage
-- nmap --script broadcast-tellstick-discover
--
-- @output
-- | broadcast-tellstick-discover: 
-- |   192.168.0.100
-- |     Product: TellStickNet
-- |     MAC: ACCA12345678
-- |     Activation code: 8QABCDEFGH
-- |_    Version: 3
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

prerule = function() return ( nmap.address_family() == 'inet' ) end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function()
	local socket = nmap.new_socket("udp")
	local host, port = { ip = "255.255.255.255" }, { number = 30303, protocol = "udp" }
	
	socket:set_timeout(5000)
	if ( not(socket:sendto(host, port, "D")) ) then
		return fail("Failed to send discovery request to server")
	end

	local output = {}

	while( true ) do
		local status, response = socket:receive()
		if ( not(status) ) then
			break
		end

		local status, _, _, ip = socket:get_info()
		if ( not(status) ) then
			stdnse.print_debug(2, "Failed to get socket information")
			break
		end

		local prod, mac, activation, version = response:match("^([^:]*):([^:]*):([^:]*):([^:]*)$")
		if ( prod and mac and activation and version ) then
			local output_part = {
				name = ip,
				("Product: %s"):format(prod),
				("MAC: %s"):format(mac),
				("Activation code: %s"):format(activation),
				("Version: %s"):format(version)
			}
			table.insert(output, output_part)
		end
	end
	
	if ( 0 < #output ) then
		return stdnse.format_output(true, output)
	end
end
