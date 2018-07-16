local nmap = require "nmap"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Checks if a VNC server is vulnerable to the RealVNC authentication bypass
(CVE-2006-2369).
]]
author = "Brandon Enright"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @see vnc-brute.nse
-- @see vnc-title.nse
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 5900/tcp open  vnc     VNC (protocol 3.8)
-- | realvnc-auth-bypass:
-- |   VULNERABLE:
-- |   RealVNC 4.1.0 - 4.1.1 Authentication Bypass
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2006-2369
-- |     Risk factor: High  CVSSv2: 7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)
-- |       RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP and
-- |       Cisco CallManager, allows remote attackers to bypass authentication via a
-- |       request in which the client specifies an insecure security type such as
-- |       "Type 1 - None", which is accepted even if it is not offered by the server.
-- |     Disclosure date: 2006-05-08
-- |     References:
-- |       http://www.intelliadmin.com/index.php/2006/05/security-flaw-in-realvnc-411/
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2369
categories = {"auth", "safe", "vuln"}


portrule = shortport.port_or_service({5900,5901,5902}, "vnc")

action = function(host, port)
  local socket = nmap.new_socket()
  local result
  local status = true

  local vuln = {
    title = "RealVNC 4.1.0 - 4.1.1 Authentication Bypass",
    IDS = { CVE = "CVE-2006-2369" },
    risk_factor = "High",
    scores = {
      CVSSv2 = "7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)",
    },
    description = [[
RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP and
Cisco CallManager, allows remote attackers to bypass authentication via a
request in which the client specifies an insecure security type such as
"Type 1 - None", which is accepted even if it is not offered by the server.]],
    references = {
      'http://www.intelliadmin.com/index.php/2006/05/security-flaw-in-realvnc-411/',
    },
    dates = {
      disclosure = {year = '2006', month = '05', day = '08'},
    },
    state = vulns.STATE.NOT_VULN,
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  socket:connect(host, port)

  status, result = socket:receive_lines(1)

  if (not status) then
    socket:close()
    return report:make_output(vuln)
  end

  socket:send("RFB 003.008\n")
  status, result = socket:receive_bytes(2)

  if not status then
    socket:close()
    return report:make_output(vuln)
  end

  local numtypes = result:byte(1)
  for i=1, numtypes do
    local sectype = result:byte(i+1)
    if sectype == 1 then
      --already supports None auth
      socket:close()
      return report:make_output(vuln)
    end
  end

  socket:send("\001")
  status, result = socket:receive_bytes(4)

  if (not status or result ~= "\000\000\000\000") then
    socket:close()
    return report:make_output(vuln)
  end

  -- VULNERABLE!
  vuln.state = vulns.STATE.VULN

  socket:close()
  -- Cache result for other scripts to exploit.
  local reg = host.registry[SCRIPT_NAME] or {}
  reg[port.number] = true
  host.registry[SCRIPT_NAME] = reg

  return report:make_output(vuln)
end
