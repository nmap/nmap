description = [[
Retrieves the day and time from the UDP Daytime service.
]]

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(13, "daytime", {"tcp", "udp"})

action = function(host, port)
	local status, result = comm.exchange(host, port, "dummy", {lines=1, proto=port.protocol})

	if status then
		return result
	end
end
