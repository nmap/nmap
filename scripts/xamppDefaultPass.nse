id = "XAMPP default pwd"

description = "If the remote host is running XAMP (an Apache distribution\
designed for easy installation and administration) and XAMPP's FTP server is\
allows access with nobody/xampp then we report it."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"vulnerability"}

require "shortport"

portrule = shortport.port_or_service(21, "ftp")

login = function(socket, user, pass)
	res = ""
	status, err = socket:send("USER " .. user .. "\n")
	status, err = socket:send("PASS " .. pass .. "\n")

	-- consume the banner and stuff
	while true do
		status, res = socket:receive_lines(1)
		if 
			not string.match(res, "^220") 
			and not string.match(res, "^331 ") 
		then
			break
		end
	end

	-- are we logged in?
	if string.match(res, "^230") then
		return "Login success with u/p: " .. user .. "/" .. pass
	end
end

action = function(host, port)
	socket = nmap.new_socket()

	socket:connect(host.ip, port.number)
	res = login(socket, "nobody", "e0e0e0e0")
	socket:close()

	socket:connect(host.ip, port.number)
	res = login(socket, "nobody", "xampp")
	socket:close()
	
	return  res
end

