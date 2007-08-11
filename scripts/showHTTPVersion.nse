description = "Demonstration of a version detection NSE script. It checks and reports\
the version of a remote web server. For real life purposes it is better to use the\
Nmap version detection.\
Author: Diman Todorov\
License: see nmaps' COPYING for license"

id = "HTTP version"

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

-- add this script to "version" if you really want to execute it
-- keep in mind you can (and should) only execute it with -sV
categories = {""}
-- categories = {"version"}

runlevel = 1.0

require "shortport"

portrule = shortport.port_or_service(80, "http")

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
