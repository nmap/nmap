id="Skype v2"
description="Determines if remote service is Skype protocol version 2"
author = "Brandon Enright <bmenrigh@ucsd.edu>" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
	if 	(port.number == 80 or
		port.number == 443 or
		port.service == nil or
		port.service == "" or
		port.service == "unknown")
		and port.protocol == "tcp"
		and port.state == "open"
		and port.service ~= "http"
		and port.service ~= "ssl/http"
	then
		return true
	else
		return false
	end
end

action = function(host, port)

	local socket = nmap.new_socket()
	local result;
	local status = true

	socket:connect(host.ip, port.number, port.protocol)
       	socket:send("GET / HTTP/1.0\r\n\r\n")

	status, result = socket:receive_bytes(26);

	if (not status) then
		socket:close()
		return
	end

	if (result ~= "HTTP/1.0 404 Not Found\r\n\r\n") then
		socket:close()
		return
	end
	
	socket:close();
	
	-- So far so good, now see if we get random data for another request

	socket:connect(host.ip, port.number, port.protocol)
       	socket:send("random data\r\n\r\n")

	status, result = socket:receive_bytes(15);

	if (not status) then
		socket:close()
		return
	end

	if string.match(result, "[^%s!-~].*[^%s!-~].*[^%s!-~]") then
		socket:close()
		port.version.name = "skype2"
		port.version.product = "Skype"
		port.version.confidence = 10
		port.version.fingerprint = nil
		nmap.set_port_version(host, port, "hardmatched")
		return	
		-- return "Skype v2 server detected"
	end

	socket:close();

	return
end
