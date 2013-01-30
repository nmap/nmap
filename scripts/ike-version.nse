local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local ike = require "ike"


description=[[
	Get information from an IKE service.
	Tests the service with both Main and Aggressive Mode. 
	Sends multiple transforms in a single request, so currently, 
	only four packets are sent to the host.
]]


---
-- @output
-- PORT    STATE SERVICE REASON       VERSION
-- 500/udp open  isakmp  udp-response Cisco VPN Concentrator 3000 4.0.7
-- Service Info: OS: pSOS+; Device: VPN; CPE: cpe:/h:cisco:concentrator
---


author = "Jesper Kueckelhahn"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe", "version"}

portrule = shortport.port_or_service(500, "isakmp", "udp")


-- Test different methods for getting version 
-- 
local function get_version(host, port)
	local packet, version, t 
	local auth			= {"psk", "rsa", "Hybrid", "XAUTH"}
	local encryption	= {"des", "3des", "aes/128", "aes/192", "aes/256"}
	local hash			= {"md5", "sha1"}
	local group			= {"768", "1024", "1536"}


	-- generate transforms
	t = {}
	for h,a in pairs(auth) do
		for i,e in pairs(encryption) do
			for j,h in pairs(hash) do
				for k,g in pairs(group) do
					table.insert(t, { ['auth'] = a, ['encryption'] = e, ['hash'] = h, ['group'] = g});
				end
			end
		end
	end


	-- try aggressive mode (diffie hellman group 2)
	local diffie = 2
	stdnse.print_debug(1, "Sending Aggressive mode packet ...")
	packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, 'vpngroup')
	version = ike.send_request(host, port, packet)
	if version.success then
		return version
	end
	stdnse.print_debug(1, "Aggressive mode (dh 2) failed")

	-- try aggressive mode (diffie hellman group 1)
	diffie = 1
	stdnse.print_debug(1, "Sending Aggressive mode packet ...")
	packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, 'vpngroup')
	version = ike.send_request(host, port, packet)
	if version.success then
		return version
	end
	stdnse.print_debug(1, "Aggressive mode (dh 1) failed")

	-- try aggressive mode (diffie hellman group 2, no id)
	-- some checkpoint devices respond to this
	local diffie = 2
	stdnse.print_debug(1, "Sending Aggressive mode packet ...")
	packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, '')
	version = ike.send_request(host, port, packet)
	if version.success then
		return version
	end
	stdnse.print_debug(1, "Aggressive mode (dh 2, no id) failed")

	-- try main mode
	stdnse.print_debug(1, "Sending Main mode packet ...")
	packet = ike.request(port.number, port.protocol, 'Main', t, '')
	version = ike.send_request(host, port, packet)
	if version.success then
		return version
	end
	stdnse.print_debug(1, "Main mode failed")

	stdnse.print_debug(1, "Version detection not possible")
	return false
end


action = function( host, port )
	local ike_response = get_version(host, port)

	if ike_response then

		-- Extra information found in the response. Kept for future reference.
		-- local mode = ike_response['mode']
		-- local vids = ike_response['vids']

		local info = ike_response['info']
		if info.vendor ~= nil then
			port.version.product = info.vendor.vendor
			port.version.version = info.vendor.version
			port.version.ostype  = info.vendor.ostype
			port.version.devicetype = info.vendor.devicetype
			table.insert(port.version.cpe, info.vendor.cpe)

			nmap.set_port_version(host, port, "hardmatched")
			nmap.set_port_state(host, port, "open")
		end
	end
	stdnse.print_debug(1, "Version: %s", port.version.product )
	return
end



