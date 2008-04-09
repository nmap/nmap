id = "Service owner"

description = "Opens a connection to the scanned port, opens a connection to port 113, queries the owner\
of the service on the scanned port and prints it."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe"}

portrule = function(host, port) 
	local identd, decision

	local auth_port = { number=113, protocol="tcp" }
	identd = nmap.get_port_state(host, auth_port)

	if 
		identd ~= nil
		and identd.state == "open" 
	then
		decision = true
	else
		decision = false
	end

	return decision
end

action = function(host, port)
	local owner = ""

	local client_ident = nmap.new_socket()
	local client_service = nmap.new_socket()

	local catch = function()
		client_ident:close()
		client_service:close()
	end

	local try = nmap.new_try(catch)

	try(client_ident:connect(host.ip, 113))
	try(client_service:connect(host.ip, port.number))

	local localip, localport, remoteip, remoteport = try(client_service:get_info())

	local request = port.number .. ", " .. localport .. "\n"

	try(client_ident:send(request))

	owner = try(client_ident:receive_lines(1))

	if string.match(owner, "ERROR") then 
		owner = nil
	--	owner = "Service owner could not be determined: " .. owner
	else
		owner = string.match(owner, "USERID : .+ : (.+)\n", 1)
	end

	try(client_ident:close())
	try(client_service:close())

	return owner
end

