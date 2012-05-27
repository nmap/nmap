local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Checks if a VNC server is vulnerable to the RealVNC authentication bypass
(CVE-2006-2369).
]]
author = "Brandon Enright"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 5900/tcp open  vnc     VNC (protocol 3.8)
-- |_realvnc-auth-bypass: Vulnerable

categories = {"auth", "default", "safe"}


portrule = shortport.port_or_service(5900, "vnc")

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	local status = true

	socket:connect(host, port)
	
	status, result = socket:receive_lines(1)

	if (not status) then
		socket:close()
		return
	end

	socket:send("RFB 003.008\n")
	status, result = socket:receive_bytes(2)

	if (not status or result ~= "\001\002") then
		socket:close()
		return
	end

	socket:send("\001")
	status, result = socket:receive_bytes(4)

	if (not status or result ~= "\000\000\000\000") then
		socket:close()
		return
	end

	socket:close()

	return "Vulnerable"
end
