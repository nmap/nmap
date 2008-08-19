--- This script connects to a UDP chargen service and attempts to read
-- some data.

id = "Chargen"

description = "Connects to the UDP chargen service and tries to read some bytes"

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
