description = [[
Retrieves the day and time from the UDP Daytime service.
]]

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(13, "daytime", {"tcp", "udp"})

action = function(host, port)
	local status, result = comm.exchange(host, port, "dummy", {lines=1, proto=port.proto})

	if status then
		return "Daytime: " .. result
	end
end
