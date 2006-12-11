id = "Daytime"

description = "Connects to the UDP daytime service and on success prints the daytime."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo"}

portrule = function(host, port)
	if 	port.number == 13
		and port.service == "daytime"
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
		return "Daytime: " .. result
	end
end
