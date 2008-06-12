id = "Daytime"

description = "Connects to the UDP daytime service and on success prints the daytime."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(13, "daytime", "udp")

action = function(host, port)
	local status, result = comm.exchange(host, port, "dummy", {lines=1, proto="udp"})

	if status then
		return "Daytime: " .. result
	end
end
