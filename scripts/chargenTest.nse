id = "Chargen"

description = "Connects to the UDP chargen service and tries to read some bytes"

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo"}

portrule = function(host, port)
	if 	port.number == 19
		and port.service == "chargen"
		and port.protocol == "udp"
	then
		return true
	else
		return false
	end
end

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
