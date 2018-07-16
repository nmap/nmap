local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local json = require "json"

description = [[
Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1 that
allows unauthenticated users to inject content in posts.

The script connects to the Wordpress REST API to obtain the list of published posts and
grabs the user id and date from there. Then it attempts to update the date field in the
post with the same date information we just obtained. If the request doesn’t return an
error, we mark the server as vulnerable.

References:
https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html

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
-- |_      https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html
--
-- @xmloutput
-- <table key="CVE-2017-1001000">
-- <elem key="title">Content Injection in Wordpress REST API</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-1001000</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv2">5.0 (MEDIUM)</elem>
-- </table>
-- <table key="description">
-- <elem>The privilege escalation vulnerability in WordPress REST API allows&#xa; the visitors to edit
-- any post on the site.&#xa; Versions 4.7.0 and 4.7.1 are known to be affected&#xa;
-- </elem>
-- </table>
-- <table key="refs">
-- <elem>https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html</elem>
-- </table>
-- </table>
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

  if response.status and  response.status == 200 then
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
          'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html'
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

    --If response is correct, means the site allowed the modification
    --of the post and it is vulnerable.
    if(response1.status and response1.status==200) then
      vuln_table.state = vulns.STATE.VULN
    end
    return vulnReport:make_output(vuln_table)
  end
end
