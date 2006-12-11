id = "Echo"

description = "Connects to the UDP echo service, sends a string, receives a string and if both\
strings are equal reports success."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo"}

portrule = function(host, port)
	if 	port.number == 7
		and port.service == "echo"
		and port.protocol == "udp"
	then
		return true
	else
		return false
	end
end

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
