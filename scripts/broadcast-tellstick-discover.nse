description=[[
Discovers Telldus Technologies TellStickNet devices on the LAN.
]]

---
-- @usage
-- nmap --script broadcast-tellstick-discover
--
-- @output
-- | broadcast-tellstick-discover: 
-- |   Product: TellStickNet
-- |   MAC: ACCA12345678
-- |   Activation code: 8QABCDEFGH
-- |_  Version: 3
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

	local status, response = socket:receive()
	if ( not(status) ) then
		return fail("Failed to receive response from server")
	end

	local prod, mac, activation, version = response:match("^([^:]*):([^:]*):([^:]*):([^:]*)$")
	if ( not(prod) or not(mac) or not(activation) or not(version) ) then
		return
	end
	
	local output = {
		("Product: %s"):format(prod),
		("MAC: %s"):format(mac),
		("Activation code: %s"):format(activation),
		("Version: %s"):format(version)
	}	
	return stdnse.format_output(true, output)
end