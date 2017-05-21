local natpmp = require "natpmp"
local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Gets the routers WAN IP using the NAT Port Mapping Protocol (NAT-PMP).
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

---
--@usage
-- nmap -sU -p 5351 --script=nat-pmp-info <target>
-- @output
-- | nat-pmp-info:
-- |_  WAN IP: 192.0.2.13
-- @xmloutput
-- <elem key="WAN IP">192.0.2.13</elem>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service(5351, "nat-pmp", {"udp"} )

action = function(host, port)
  local helper = natpmp.Helper:new(host, port)
  local status, response = helper:getWANIP()

  if ( status ) then
    nmap.set_port_state(host, port, "open")
    port.version.name = "nat-pmp"
    nmap.set_port_version(host, port)

    return {["WAN IP"] = response.ip}
  end
end
