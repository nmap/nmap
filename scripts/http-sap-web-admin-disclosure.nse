local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects SAP systems that are potentially vulnerable to information disclosure
through the SAP Web Administration Interface. This script checks for the presence
of the /sap/admin/public/index.html page, which may reveal sensitive information
about the SAP system.

The vulnerability is described in SAP Security Note 2258786.

This script was inspired by research from the RedRays SAP Security Team (https://redrays.io).

References:
* https://launchpad.support.sap.com/#/notes/2258786
* https://redrays.io
]]

---
-- @usage nmap -p 80 --script http-sap-web-admin-disclosure <target>
-- @usage nmap -sV --script http-sap-web-admin-disclosure <target>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-sap-web-admin-disclosure:
-- |   VULNERABLE:
-- |   SAP Web Administration Interface Information Disclosure
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       The SAP Web Administration Interface is accessible and may disclose sensitive
-- |       information about the SAP system, including installed products, versions, and
-- |       landscape configuration data.
-- |
-- |     Disclosure date: 2016-03-08
-- |     Extra Info:
-- |       This script was developed by the RedRays SAP Security Team.
-- |     References:
-- |       https://launchpad.support.sap.com/#/notes/2258786
-- |_      https://redrays.io

author = "Assistant (inspired by RedRays SAP Security Team - https://redrays.io)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = 'SAP Web Administration Interface Information Disclosure',
    state = vulns.STATE.NOT_VULN,
    description = [[
The SAP Web Administration Interface is accessible and may disclose sensitive
information about the SAP system, including installed products, versions, and
landscape configuration data.

This vulnerability was researched by the RedRays SAP Security Team.
    ]],
    references = {
      'https://launchpad.support.sap.com/#/notes/2258786',
      'https://redrays.io',
    },
    dates = {
      disclosure = {year = '2016', month = '03', day = '08'},
    },
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/sap/admin/public/index.html"
  local options = {header={}, no_cache=true, bypass_cache=true}

  options['header']['User-Agent'] = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

  local response = http.get(host, port, path, options)
  if response and response.status == 200 then
    if string.find(response.body, '<title>Administration</title>') then
      vuln.state = vulns.STATE.LIKELY_VULN
      vuln.check_results = string.format("Found SAP Web Administration Interface at %s", path)
      return vuln_report:make_output(vuln)
    end
  end

  return vuln_report:make_output(vuln)
end
