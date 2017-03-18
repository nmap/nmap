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

  This is a serious vulnerability that can be misused in different ways to 
  compromise a vulnerable site. 
  ]]

---
-- @usage
-- nmap --script http-wordpress-contentinjection --script-args http-wordpress-contentinjection.uri="uri" <target>
-- nmap --script http-wordpress-contentinjection <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-wordpress-contentinjection:
-- |   VULNERABLE:
-- |   Content Injection in Wordpress REST API
-- |     State: VULNERABLE (Exploitable)
-- |     Risk Factor: Medium  CVSS2: 6.4 
-- |       The privilege escalation vulnerability in WordPress REST API allows
-- |       the visitors to edit any post on the site 
-- |       Versions 4.7.0 and 4.7.1 are known to be affected
-- |    
-- |     References:
-- |       http://securityaffairs.co/wordpress/55892/hacking/wordpress-zero-day-content-injection.html
-- |       https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html
-- |_      https://www.exploit-db.com/exploits/41223
--
-- @args http-wordpress-contentinjection.uri Wordpress root directory on the website. Default: /
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
      risk_factor = "Medium",
      description = [[
The privilege escalation vulnerability in WordPress REST API allows
the visitors to edit any post on the site .
Versions 4.7.0 and 4.7.1 are known to be affected.
      ]],
      scores = {
      CVSS2 =  '6.4'
      },
      references = {
          'http://securityaffairs.co/wordpress/55892/hacking/wordpress-zero-day-content-injection.html',
          'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html',
          'https://www.exploit-db.com/exploits/41223'
      },
    }

    local id, data 
    local status, json_data = json.parse(response.body)

    --Parsing the json_data to get the ID of the first post and the date.
    id=json_data[1].id
    content=json_data[1].date

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

    --If response is correct, means the site allowed the modification
    --of the post and it is vulnerable.
    if(response1.status==200) then
      vuln_table.state = vulns.STATE.VULN
    end
    return vulnReport:make_output(vuln_table)
  end
end
