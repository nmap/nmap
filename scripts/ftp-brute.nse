description = [[
Tries to get FTP login credentials by guessing usernames and passwords.
]]

---
-- @output
-- 21/tcp open  ftp
-- |_ ftp-auth: Login success with u/p: nobody/xampp
--
-- 2008-11-06 Vlatko Kosturjak <kost@linux.hr>
-- Modified xampp-default-auth script to generic ftp-brute script

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"

portrule = shortport.port_or_service(21, "ftp")

login = function(socket, user, pass)
	local status, err
	local res = ""
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
	local res
	local socket = nmap.new_socket()
	local authcombinations = { 
		{user="nobody", password="xampp"}, --- XAMPP default ftp
	}

	for _, combination in pairs (authcombinations) do
		socket:connect(host.ip, port.number)
		res = login(socket, combination.user, combination.password)
		socket:close()
	end
	
	return  res
end

