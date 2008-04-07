description = "Demonstration of a version detection NSE script. It checks and reports\
the version of a remote web server. For real life purposes it is better to use the\
Nmap version detection."

id = "HTTP version"

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

-- add this script to "version" if you really want to execute it
-- keep in mind you can (and should) only execute it with -sV
categories = {""}
-- categories = {"version"}

runlevel = 1.0

require "shortport"

portrule = function(host, port)


	if 
		-- remove next line if you really want to run this script
		false and
		(	port.number == 80
		or port.service == "http" )
		and port.protocol == "tcp" 
		and port.state == "open"
		-- and host.name ~= nil 
		-- and string.match(host.name, "www.+") 
	then
		return true
	else
		return false
	end
end

-- portrule = shortport.port_or_service(80, "http")

action = function(host, port)

	local query = "GET / HTTP/2.1\r\n"
	query = query .. "Accept: */*\r\n"
	query = query .. "Accept-Language: en\r\n"
	query = query .. "User-Agent: Nmap NSE\r\n"
	query = query .. "Host: " .. host.ip .. ":" .. port.number .. "\r\n\r\n"

	local socket = nmap.new_socket()
	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	try(socket:connect(host.ip, port.number))
	try(socket:send(query))

	local response = ""
	local lines
	local status
	local value

	while true do
		status, lines = socket:receive_lines(1)

		if not status or value then
			break
		end

		response = response .. lines
		value = string.match(response, "Server: (.-)\n")
	end

	try(socket:close())
	socket:close()

	if value then
		port.version.name = "[Name]"
		port.version.confidence = 10
		port.version.product = "[Product]"
		port.version.version = "[Version]"
		port.version.extrainfo = "[ExtraInfo]"
		port.version.hostname = "[HostName]"
		port.version.ostype = "[OSType]"
		port.version.devicetype = "[DeviceType]"

		port.version.service_tunnel = "none"
		port.version.fingerprint = nil
		nmap.set_port_version(host, port, "hardmatched")
	end
end
