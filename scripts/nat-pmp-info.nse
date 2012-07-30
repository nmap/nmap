local natpmp = require "natpmp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Get's the routers WAN IP using the NAT Port Mapping Protocol (NAT-PMP). 
The NAT-PMP protocol is supported by a broad range of routers including:
  - Apple AirPort Express
  - Apple AirPort Extreme
  - Apple Time Capsule
  - DD-WRT
  - OpenWrt v8.09 or higher, with MiniUPnP daemon
  - pfSense v2.0
  - Tarifa (firmware) (Linksys WRT54G/GL/GS)
  - Tomato Firmware v1.24 or higher. (Linksys WRT54G/GL/GS and many more)
  - Peplink Balance
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service(5351, "nat-pmp", {"udp"} )

action = function(host, port)
	local helper = natpmp.Helper:new(host, port)
	local status, response = helper:getWANIP()
	
	if ( status ) then
		nmap.set_port_state(host, port, "open")
		port.version.name = "nat-pmp"
		nmap.set_port_version(host, port)
		
		return stdnse.format_output(true, ("WAN IP: %s"):format(response.ip))
	end
end
