id = "MS Windows shell"

description = "If port 8888 is open and it echos a specific string then we\
might have found an open MSWindows shell."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"backdoor"}

require "shortport"

portrule = shortport.port_or_service(8888, "auth")

action = function(host, port)
	local status = 0
	local result = ""

	local client_ident = nmap.new_socket()

	client_ident:connect(host.ip, port.number)

	status, result = client_ident:receive_bytes(4096)

	client_ident:close()

	if string.match(result, "Microsoft Windows") then
		return "Possible open windows shell found."
	end
end

