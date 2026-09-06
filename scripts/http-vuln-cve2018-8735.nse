local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"


description = [[
NagiosXI versions before 5.4.13 are vulnerable to an unauthenticated remote root exploit.  This unobtrusive script simply sends a single HTTP GET 
request for /nagiosxi/login.php and matches strings to identify the product and version.
]]

---
-- @usage nmap -p 80 --script http-vuln-cve2018-8735 <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2018-8735: 
-- |   VULNERABLE:
-- |   NagiosXI < 5.4.13 Root RCE
-- |     State: VULNERABLE
-- |     IDs:  1:CVE-2018-8734  2:CVE-2018-8733  3:CVE-2018-8736  CVE:CVE-2018-8735
-- |     Risk factor: High  CVSSv2: 10 HIGH  CVSSv3: 9.8 CRITICAL
-- |       NagiosXI versions before 5.4.13 are vulnerable to an unauthenticated remote root exploit.
-- |     Disclosure date: 2018-04-17
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8735
-- |_      http://blog.redactedsec.net/exploits/2018/04/26/nagios.html
---

-- @changelog
--  *initial version

-----------------------------------------------------------------------

author = "Cale Smith @0xC413"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local vuln_table = {
    title = "NagiosXI < 5.4.13 Root RCE",
    IDS = {CVE = 'CVE-2018-8735' ,'CVE-2018-8734','CVE-2018-8733','CVE-2018-8736'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "10 HIGH",
      CVSSv3 = "9.8 CRITICAL"
    },
    description = [[NagiosXI versions before 5.4.13 are vulnerable to an unauthenticated remote root exploit.]],
    references = {
        'http://blog.redactedsec.net/exploits/2018/04/26/nagios.html',
        },
    dates = {
      disclosure = {year = '2018', month = '04', day = '17'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  local uri = stdnse.get_script_args(SCRIPT_NAME .. '.uri') or '/'
  uri = uri .. 'nagiosxi/login.php'

  local begin_delim = 'name="version" value="'
  local end_delim = '"'
  local start_idx
  local end_idx
  local version

  stdnse.debug1("HTTP GET uri %s", uri)
  local response = http.get(host, port, uri)

  if response.status == 200 then

    if http.response_contains(response, "nagiosxi") then
      stdnse.debug1("****We found NagiosXI, that's cool!")

      f00, start_idx = string.find(response.body , begin_delim)
      
      version = string.sub(response.body, start_idx+1)
      end_idx, f00 = string.find(version,end_delim)

      version = string.sub(version, 0, 6)
      stdnse.debug1("******NagiosXI version: %s", version)

      version = string.gsub(version,"%.","")
      version = string.gsub(version,"\"","")
      version = tonumber(version)

      --alert on versions before 5.4.13
      if version < 5413 then 
        stdnse.debug1("Vulnerable NagiosXI version found!")
        vuln_table.state = vulns.STATE.VULN
      end
    end 
end
  return vuln_report:make_output(vuln_table)
end

