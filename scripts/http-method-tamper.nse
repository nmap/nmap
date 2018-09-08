description = [[
Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering.
If an array of paths to check is not set, it will crawl the web server and perform the check against any
password protected resource that it finds.

The script determines if the protected URI is vulnerable by performing HTTP verb tampering and monitoring
 the status codes. First, it uses a HEAD request, then a POST request and finally a random generated string
( This last one is useful when web servers treat unknown request methods as a GET request. This is the case
 for PHP servers ).

If the table <code>paths</code> is set, it will attempt to access the given URIs. Otherwise, a web crawler
is initiated to try to find protected resources. Note that in a PHP environment with .htaccess files you need to specify a
path to a file rather than a directory to find misconfigured .htaccess files.

References:
* http://www.imperva.com/resources/glossary/http_verb_tampering.html
* https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
* http://www.mkit.com.ar/labs/htexploit/
* http://capec.mitre.org/data/definitions/274.html
]]

---
-- @usage nmap -sV --script http-method-tamper <target>
-- @usage nmap -p80 --script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-method-tamper:
-- |   VULNERABLE:
-- |   Authentication bypass by HTTP verb tampering
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       This web server contains password protected resources vulnerable to authentication bypass
-- |       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
-- |        common HTTP methods and in misconfigured .htaccess files.
-- |
-- |     Extra information:
-- |
-- |   URIs suspected to be vulnerable to HTTP verb tampering:
-- |     /method-tamper/protected/pass.txt [POST]
-- |
-- |     References:
-- |       http://www.imperva.com/resources/glossary/http_verb_tampering.html
-- |       http://www.mkit.com.ar/labs/htexploit/
-- |       http://capec.mitre.org/data/definitions/274.html
-- |_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
--
-- @args http-method-tamper.uri Base URI to crawl. Not applicable if <code>http-method-tamper.paths</code> is set.
-- @args http-method-tamper.paths Array of paths to check. If not set, the script will crawl the web server.
-- @args http-method-tamper.timeout Web crawler timeout. Default: 10s
---

author = "Paulino Calderon <calderon@websec.mx>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local httpspider = require "httpspider"
local vulns = require "vulns"
local url = require "url"
local string = require "string"
local rand = require "rand"

portrule = shortport.http

--
-- Checks if the web server does not return status 401 when requesting with other HTTP verbs.
-- First, it tries with HEAD, POST and then with a random string.
--
local function probe_http_verbs(host, port, uri)
  stdnse.debug2("Tampering HTTP verbs %s", uri)
  local head_req = http.head(host, port, uri)
  if head_req and head_req.status ~= 401 then
    return true, "HEAD"
  end
  local post_req = http.post(host, port, uri)
  if post_req and post_req.status ~= 401 then
    return true, "POST"
  end
  --With a random generated verb we look for 400 and 501 status
  local random_verb_req = http.generic_request(host, port, rand.random_alpha(4):upper(), uri)
  local retcodes = {
    [400] = true, -- Bad Request
    [401] = true, -- Authentication needed
    [501] = true, -- Invalid method
  }
  if random_verb_req and not retcodes[random_verb_req.status] then
    return true, "GENERIC"
  end

  return false
end

action = function(host, port)
  local vuln_uris = {}
  local paths = stdnse.get_script_args(SCRIPT_NAME..".paths")
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
  timeout = (timeout or 10) * 1000
  local vuln = {
    title = 'Authentication bypass by HTTP verb tampering',
    state = vulns.STATE.NOT_VULN,
    description = [[
This web server contains password protected resources vulnerable to authentication bypass
vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
 common HTTP methods and in misconfigured .htaccess files.
       ]],
    references = {
      'http://www.mkit.com.ar/labs/htexploit/',
      'http://www.imperva.com/resources/glossary/http_verb_tampering.html',
      'https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29',
      'http://capec.mitre.org/data/definitions/274.html'
    }
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- If paths is not set, crawl the web server looking for http 401 status
  if not(paths) then
    local crawler = httpspider.Crawler:new(host, port, uri, { scriptname = SCRIPT_NAME } )
    crawler:set_timeout(timeout)

    while(true) do
      local status, r = crawler:crawl()
      if ( not(status) ) then
        if ( r.err ) then
          return stdnse.format_output(false, r.reason)
        else
          break
        end
      end
      if r.response.status == 401 then
        stdnse.debug2("%s is protected! Let's try some verb tampering...", tostring(r.url))
        local parsed = url.parse(tostring(r.url))
        local probe_status, probe_type = probe_http_verbs(host, port, parsed.path)
        if probe_status then
          stdnse.debug1("Vulnerable URI %s", uri)
          table.insert(vuln_uris, parsed.path..string.format(" [%s]", probe_type))
        end
      end
    end
  else
    -- Paths were set, check them and exit. No crawling here.

    -- convert single string entry to table
    if ( type(paths) == "string" ) then
      paths = { paths }
    end
    -- iterate through given paths/files
    for _, path in ipairs(paths) do
      local path_req = http.get(host, port, path)

      if path_req.status == 401 then
        local probe_status, probe_type = probe_http_verbs(host, port, path)
        if probe_status then
          stdnse.debug1("Vulnerable URI %s", path)
          table.insert(vuln_uris, path..string.format(" [%s]", probe_type))
        end
      end

    end
  end

  if ( #vuln_uris > 0 ) then
    vuln.state = vulns.STATE.EXPLOIT
    vuln_uris.name = "URIs suspected to be vulnerable to HTTP verb tampering:"
    vuln.extra_info = stdnse.format_output(true, vuln_uris)
  end

  return vuln_report:make_output(vuln)
end
