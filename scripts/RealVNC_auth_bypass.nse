id="RealVNC Authentication Bypass (CVE-2006-2369)"
description="Checks to see if the VNC Server is vulnerable to the RealVNC authentication bypass."
author = "Brandon Enright <bmenrigh@ucsd.edu>" 
license = "See nmaps COPYING for licence"

categories = {"backdoor"}

portrule = function(host, port)
	if 	(port.number == 5900
		or port.service == "vnc")
		and port.protocol == "tcp"
		and port.state == "open"
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	local status = true

	socket:connect(host.ip, port.number, port.protocol)
	
	status, result = socket:receive_lines(1)

	if (result == "TIMEOUT") then
		socket:close()
		return
	end

	socket:send("RFB 003.008\n")
	status, result = socket:receive_bytes(2)

	if (result == "TIMEOUT") then
		socket:close()
		return
	end

	if (result ~= "\001\002") then
		socket:close()
		return
	end	

	socket:send("\001")
	status, result = socket:receive_bytes(4)

	if (result == "TIMEOUT") then
		socket:close()
		return
	end

	if (result ~= "\000\000\000\000") then
		socket:close()
		return
	end	

	socket:close()

	return "Vulnerable"
end
