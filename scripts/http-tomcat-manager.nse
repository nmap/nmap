description = [[
Detects default or no password for the Tomcat Manager application,
which then allows Remote Code Execution by uploading a malicious .WAR file.

The following tomcat versions are likely to be vulnerable:
4, 5, 6, 7

Reference: https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_deploy
]]

---
-- @usage
-- nmap -sV --script http-tomcat-manager <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-tomcat-manager:
-- |   VULNERABLE:
-- |   Tomcat Manager application with default or no password set
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       Tomcat Manager application has been found to have a known default or no password allowing for remote code execution by uploading malicious .WAR file.
-- |
-- |     References:
-- |_      https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload
---

author = "@pwndad"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.port_or_service({80, 443, 8080}, {"http","https"})

action = function(host, port)
  local response = http.get(host, port, "/manager/html/", { redirect_ok = false, no_cache = true, header = {["Authorization"] = "Basic dG9tY2F0OnRvbWNhdA=="} })
  local server = response.header and response.header['server'] or ""
  local vuln_table = {
    title = "Tomcat Manager application with default or no password set",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
Tomcat Manager application has been found to have a known default or no password allowing for remote code execution by uploading malicious .WAR file.
]],
    references = {
      'https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload',
    }
  }
  if ( response.status == 200 ) then
    vuln_table.state = vulns.STATE.VULN
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    return report:make_output(vuln_table)
  end
  return
end
