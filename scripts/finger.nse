id = "Finger Results"
description = [[
Attempts to get a list of usernames via the finger service.
]]

author = "Eddie Bell <ejlbell@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(79, "finger")

action = function(host, port)
	local try = nmap.new_try()

	return try(comm.exchange(host, port, "\r\n",
        	{lines=100, proto=port.protocol, timeout=5000}))
end
