id="Anonymous FTP"

description="Checks to see if a FTP server allows anonymous logins"

author = "ejlb <ejlbell@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"intrusive"}

portrule = function(host, port)
	if 	port.number == 21
		and port.service == "ftp"
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
	local result;
	local status = true
	local isAnon = false

	socket:connect(host.ip, port.number, port.protocol)
       	socket:send("USER anonymous\r\n")
	socket:send("PASS IEUser@\r\n")

        while status do
		status, result = socket:receive_lines(1);
		if string.match(result, "^230") then
			isAnon = true;
			break;
		end
	end

	socket:close();

	if(isAnon) then
		return "FTP: Anonymous login allowed"
	end
end
