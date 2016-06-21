description = [[
Tests whether a JBoss target is vulnerable to jmx console authentication bypass (CVE-2010-0738).

It works by checking if the target paths require authentication or redirect to a login page that could be
bypassed via a HEAD request. RFC 2616 specifies that the HEAD request should be treated exactly like GET but
with no returned response body. The script also detects if the URL does not require authentication at all.

For more information, see:
* CVE-2010-0738 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0738
* http://www.imperva.com/resources/glossary/http_verb_tampering.html
* https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

]]

---
-- @usage
-- nmap --script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}' <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2010-0738:
-- |_  /jmx-console/: Authentication bypass.
--
-- @args http-vuln-cve2010-0738.paths Array of paths to check. Defaults
-- to <code>{"/jmx-console/"}</code>.

author = "Hani Benhabiles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth", "vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

portrule = shortport.http

action = function(host, port)
  local paths = stdnse.get_script_args(SCRIPT_NAME..".paths")
  local result = {}

  -- convert single string entry to table
  if ( "string" == type(paths) ) then
    paths = { paths }
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- fallback to jmx-console
  paths = paths or {"/jmx-console/"}

  for _, path in ipairs(paths) do
    local getstatus = http.get(host, port, path).status

    -- Checks if HTTP authentication or a redirection to a login page is applied.
    if getstatus == 401 or getstatus == 302 then
      local headstatus = http.head(host, port, path).status
      if headstatus == 500 and path == "/jmx-console/" then
        -- JBoss authentication bypass.
        table.insert(result, ("%s: Vulnerable to CVE-2010-0738."):format(path))
      elseif headstatus == 200 then
        -- Vulnerable to authentication bypass.
        table.insert(result, ("%s: Authentication bypass possible"):format(path))
      end
      -- Checks if no authentication is required for Jmx console
      -- which is default configuration and common.
    elseif getstatus == 200 then
      table.insert(result, ("%s: Authentication was not required"):format(path))
    end
  end

  return stdnse.format_output(true, result)
end
