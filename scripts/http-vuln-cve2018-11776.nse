description = [[
Detects whether the specified URL is vulnerable to the Apache Strut2 Namespace Redirect OGNL Injection
Remote Code Execution Vulnerability (CVE-2018-11776).
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2018-11776 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-vuln-cve2018-11776:
-- |   VULNERABLE
-- |   
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-11776
-- |
-- |     Disclosure date: 2018-08-22
-- |     References:
-- |     https://cwiki.apache.org/confluence/display/WW/S2-057  
-- |     https://lgtm.com/blog/apache_struts_CVE-2018-11776  
-- |_    https://github.com/hook-s3c/CVE-2018-11776-Python-PoC  
--
-- @args http-vuln-cve2018-11776.method The HTTP method for the request. The default method is "POST".
-- @args http-vuln-cve2018-11776.path The URL path to request. The default path is "/".

author = "r00tpgp"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Apache Struts 2 Namespace Redirect OGNL Injection",
    state = vulns.STATE.NOT_VULN,
    description = [[
Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true 
(either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard 
namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no 
or wildcard namespace. 
    ]],
    IDS = {
        CVE = "CVE-2018-11776"
    },
    references = {
        'https://lgtm.com/blog/apache_struts_CVE-2018-11776',
	'https://cwiki.apache.org/confluence/display/WW/S2-057',
        'https://github.com/hook-s3c/CVE-2018-11776-Python-PoC'
    },
    dates = {
        disclosure = { year = '2018', month = '08', day = '22' }
    }
  }

 -- Ask the server a simple math question, if it answer correctly, you have a vuln server :-)

 local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
 local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
 a = math.random(1000)
 b = math.random(1000)
 c = a + b
 local response = http.generic_request(host, port, "GET", "/%24%7B" .. a .. "%2B" .. b .. "%7D" .. "/help.action") 

 if response.status == 302 and response.header.location == "/" .. c .. "/date.action" then
	 vuln.state = vulns.STATE.VULN
 end

 return vuln_report:make_output(vuln)
end
