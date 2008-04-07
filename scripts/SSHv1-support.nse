id="SSH Protocol Version 1"
description="Checks to see if SSH server supports SSH Protocol Version 1."
author = "Brandon Enright <bmenrigh@ucsd.edu>"
license = "Same as Nmap--See http://nmap.org/man/man-legal.html"
categories = {"intrusive"}

require "shortport"

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)
	local socket = nmap.new_socket()
	local result;
	local status = true;

	socket:connect(host.ip, port.number, port.protocol)
	status, result = socket:receive_lines(1);

	if (not status) then
		socket:close()
		return
	end

	if (result == "TIMEOUT") then
		socket:close()
		return
	end

	if  not string.match(result, "^SSH%-.+\n$") then
		socket:close()
		return
	end

       	socket:send("SSH-1.5-NmapNSE_1.0\n")

	-- should be able to consume at least 13 bytes
	-- key length is a 4 byte integer
	-- padding is between 1 and 8 bytes
	-- type is one byte
	-- key is at least several bytes
	status, result = socket:receive_bytes(13);

	if (not status) then
		socket:close()
		return
	end

	if (result == "TIMEOUT") then
		socket:close()
		return
	end

	if  not string.match(result, "^....[%z]+\002") then
		socket:close()
		return
	end
	
	socket:close();

	return "Server supports SSHv1"
end
