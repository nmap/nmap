id = "Echo"
description = [[
Tests the UDP echo service.
\n\n
The script sends a string, then receives a string and reports success if the
two strings are equal.
]]

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "comm"
require "shortport"

portrule = shortport.port_or_service(7, "echo", "udp")

action = function(host, port)
	local echostr = "hello there"

	local status, result = comm.exchange(host, port, echostr, {lines=1, proto="udp"})

	if (result == echostr) then
		return "UDP Echo: correct response"
	end
end
