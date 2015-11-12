local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635).

The script sends a specially crafted HTTP request with no impact on the system to detect this vulnerability.
The affected versions are Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1,
and Windows Server 2012 R2.

References:
* https://technet.microsoft.com/library/security/MS15-034
]]

---
-- @usage nmap -sV --script vuln <target>
-- @usage nmap -p80 --script http-vuln-cve2015-1635.nse <target>
-- @usage nmap -sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/' <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2015-1635:
-- |   VULNERABLE:
-- |   Remote Code Execution in HTTP.sys (MS15-034)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-1635
-- |       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
-- |       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
-- |       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
-- |
-- |     Disclosure date: 2015-04-14
-- |     References:
-- |       https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
-- @args http-vuln-cve2015-1635.uri URI to use in request. Default: /
---

author = {"Kl0nEz", "Paulino <calderon()websec.mx>"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local VULNERABLE = "Requested Range Not Satisfiable"
local PATCHED = "The request has an invalid header name"

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Remote Code Execution in HTTP.sys (MS15-034)',
    state = vulns.STATE.NOT_VULN,
    description = [[
A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
    ]],
    IDS = {CVE = 'CVE-2015-1635'},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms15-034.aspx'
    },
    dates = {
      disclosure = {year = '2015', month = '04', day = '14'},
    }
  }
  local options = {header={}}
  options['header']['Host'] = stdnse.generate_random_string(8)
  options['header']['Range'] = "bytes=0-18446744073709551615"

  local response = http.get(host, port, uri, options)
  if response.status and response.body then
    if response.status == 416 and string.find(response.body, VULNERABLE) ~= nil
    and string.find(response.header["server"], "Microsoft") ~= nil then
      vuln.state = vulns.STATE.VULN
    end
    if response.body and string.find(response.body, PATCHED) ~= nil then
      stdnse.debug2("System is patched!")
      vuln.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln)
end
