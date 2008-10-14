id = "Chargen"
description = [[
Tries to read bytes from the UDP chargen service.
]]

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(19, "chargen", "udp")

action = function(host, port)
	local status, result = comm.exchange(host, port, "dummy", {lines=1, proto="udp"})

	if status then
		return "Chargen: success"
	end
end
