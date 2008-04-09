id = "Chargen"

description = "Connects to the UDP chargen service and tries to read some bytes"

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "shortport"

portrule = shortport.port_or_service(19, "chargen", "udp")

action = function(host, port)
	local socket = nmap.new_socket()
	socket:connect(host.ip, port.number, "udp")
	socket:send("dummy")
	local status, result = socket:receive_lines(1);
	socket:close()

	if (result ~= nil) then
		return "Chargen: success"
	else
		return "Chargen: something went wrong"
	end
end
