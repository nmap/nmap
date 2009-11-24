description = [[
Attempts to retrieve a list of usernames using the finger service.
]]

author = "Eddie Bell"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(79, "finger")

action = function(host, port)
	local try = nmap.new_try()

	return try(comm.exchange(host, port, "\r\n",
        	{lines=100, proto=port.protocol, timeout=5000}))
end
