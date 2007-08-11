id = "IRC zombie"

description = "If port 113 responds before we ask it then something is fishy.\
Usually this means that the host is an irc zombie."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"malware"}

require "shortport"

portrule = shortport.port_or_service(113, "auth")

action = function(host, port)
	local status = 0
	local owner = ""

	local client_ident = nmap.new_socket()

	client_ident:connect(host.ip, port.number)

	status, owner = client_ident:receive_lines(1)

	client_ident:close()

	if owner == "TIMEOUT" then
		return
	end

	return owner
end

