description = [[
Attempts to extract system information from the UPnP service.
]]

---
-- @output
-- |  upnp-info:  System/1.0 UPnP/1.0 IGD/1.0
-- |_ Location: http://192.168.1.1:80/UPnP/IGD.xml

-- 2010-10-05 - add prerule support <patrik@cqure.net>
-- 2010-10-10 - add newtarget support <patrik@cqure.net>
-- 2010-10-29 - factored out all of the code to upnp.lua <patrik@cqure.net>

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require("shortport")
require("upnp")

---
-- Runs on UDP port 1900
portrule = shortport.portnumber(1900, "udp", {"open", "open|filtered"})

---
-- Sends UPnP discovery packet to host, 
-- and extracts service information from results
action = function(host, port)
	local helper = upnp.Helper:new( host, port )
	local status, result = helper:queryServices()

	if ( status ) then
		nmap.set_port_state(host, port, "open")
		return stdnse.format_output(true, result)
	end
end
