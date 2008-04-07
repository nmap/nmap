id = "Echo"

description = "Connects to the UDP echo service, sends a string, receives a string and if both\
strings are equal reports success."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"demo"}

require "shortport"

portrule = shortport.port_or_service(7, "echo", "udp")

action = function(host, port)
	local echostr = "hello there"
	local socket = nmap.new_socket()
	socket:connect(host.ip, port.number, "udp")
	socket:send(echostr)
	local status, result = socket:receive_lines(1);
	socket:close()

	if (result == echostr) then
		return "UDP Echo: correct response"
	end

	return
end
