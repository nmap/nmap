description = [[
Checks if a VNC server is vulnerable to the RealVNC authentication bypass
(CVE-2006-2369).
]]
author = "Brandon Enright" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "vuln", "safe"}

require "shortport"

portrule = shortport.port_or_service(5900, "vnc")

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
