description=[[
Crawls a web server and attempts to find PHP files vulnerable to reflected
cross site scripting via the variable <code>$_SERVER["PHP_SELF"]</code>.

This script crawls the webserver to create a list of PHP files and then sends
an attack vector/probe to identify PHP_SELF cross site scripting
vulnerabilities.  PHP_SELF XSS refers to reflected cross site scripting
vulnerabilities caused by the lack of sanitation of the variable
<code>$_SERVER["PHP_SELF"]</code> in PHP scripts. This variable is commonly
used in PHP scripts that display forms and when the script file name  is
needed.

Examples of Cross Site Scripting vulnerabilities in the variable $_SERVER[PHP_SELF]:
* http://www.securityfocus.com/bid/37351
* http://software-security.sans.org/blog/2011/05/02/spot-vuln-percentage
* http://websec.ca/advisories/view/xss-vulnerabilities-mantisbt-1.2.x

The attack vector/probe used is: <code>/'"/><script>alert(1)</script></code>
]]

---
-- @usage
-- nmap --script=http-phpself-xss -p80 <target>
-- nmap -sV --script http-self-xss <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-phpself-xss:
-- |   VULNERABLE:
-- |   Unsafe use of $_SERVER["PHP_SELF"] in PHP files
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.
-- |
-- |     Extra information:
-- |
-- |   Vulnerable files with proof of concept:
-- |     http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |     http://calder0n.com/sillyapp/secret/2.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |     http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |     http://calder0n.com/sillyapp/secret/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |   Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=calder0n.com
-- |     References:
-- |       https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
-- |_      http://php.net/manual/en/reserved.variables.server.php
--
-- @args http-phpself-xss.uri URI. Default: /
-- @args http-phpself-xss.timeout Spidering timeout. (default 10s)
--
-- @see http-stored-xss.nse
-- @see http-dombased-xss.nse
-- @see http-xssed.nse
author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"fuzzer", "intrusive", "vuln"}

local http = require 'http'
local httpspider = require 'httpspider'
local shortport = require 'shortport'
local url = require 'url'
local stdnse = require 'stdnse'
local vulns = require 'vulns'
local string = require 'string'
local table = require 'table'

portrule = shortport.http

-- PHP_SELF Attack vector
local PHP_SELF_PROBE = '/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E'
local probes = {}

--Checks if attack vector is in the response's body
--@param response Response table
--@return True if attack vector is found in response's body
local function check_probe_response(response)
  stdnse.debug3("Probe response:\n%s", response.body)
  if string.find(response.body, "'\"/><script>alert(1)</script>", 1, true) ~= nil then
    return true
  end
  return false
end

--Launches probe request
--@param host Hostname
--@param port Port number
--@param uri URL String
--@return True if page is vulnerable/attack vector was found in body
local function launch_probe(host, port, uri)
  local probe_response

  --We avoid repeating probes.
  --This is a temp fix since httpspider do not keep track of previously parsed links at the moment.
  if probes[uri] then
    return false
  end

  stdnse.debug1("HTTP GET %s%s", uri, PHP_SELF_PROBE)
  probe_response = http.get(host, port, uri .. PHP_SELF_PROBE)

  --save probe in list to avoid repeating it
  probes[uri] = true

  if check_probe_response(probe_response) then
    return true
  end
  return false
end

---
--main
---
action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..'.timeout'))
  timeout = (timeout or 10) * 1000
  local crawler = httpspider.Crawler:new(host, port, uri, { scriptname = SCRIPT_NAME } )
  crawler:set_timeout(timeout)

  local vuln = {
       title = 'Unsafe use of $_SERVER["PHP_SELF"] in PHP files',
       state = vulns.STATE.NOT_VULN,
       description = [[
PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.
       ]],
       references = {
           'http://php.net/manual/en/reserved.variables.server.php',
           'https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)'
       }
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local vulnpages = {}
  local probed_pages= {}

  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    local parsed = url.parse(tostring(r.url))

    --Only work with .php files
    if ( parsed.path and parsed.path:match(".*.php") ) then
        local host = parsed.host
        local port = parsed.port or url.get_default_port(parsed.scheme)
        local escaped_link = parsed.path:gsub(" ", "%%20")
        if launch_probe(host,port,escaped_link) then
          table.insert(vulnpages, parsed.scheme..'://'..host..escaped_link..PHP_SELF_PROBE)
        end
      end
  end

  if ( #vulnpages > 0 ) then
    vuln.state = vulns.STATE.EXPLOIT
    vulnpages.name = "Vulnerable files with proof of concept:"
    vuln.extra_info = stdnse.format_output(true, vulnpages)..crawler:getLimitations()
  end

  return vuln_report:make_output(vuln)

end

