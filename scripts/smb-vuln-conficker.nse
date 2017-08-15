local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects Microsoft Windows systems infected by the Conficker worm. This check is dangerous and
it may crash systems.

Based loosely on the Simple Conficker Scanner, found here:
-- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/

This check was previously part of smb-check-vulns.
]]
---
--@usage
-- nmap --script smb-vuln-conficker.nse -p445 <host>
-- nmap -sU --script smb-vuln-conficker.nse -p T:139 <host>
--
--@output
--| smb-vuln-conficker:
--|   VULNERABLE:
--|   Microsoft Windows system infected by Conficker
--|     State: VULNERABLE
--|     IDs:  CVE:2008-4250
--|       This system shows signs of being infected by a variant of the worm Conficker.
--|     References:
--|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
--|       http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Win32%2fConficker
--|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=2008-4250
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

local INFECTED   = 5
local INFECTED2  = 6
local CLEAN      = 7

-- Help messages for the more common errors seen by the Conficker check.
CONFICKER_ERROR_HELP = {
  ["NT_STATUS_BAD_NETWORK_NAME"] =
  [[UNKNOWN; Network name not found (required service has crashed). (Error NT_STATUS_BAD_NETWORK_NAME)]],
  -- http://seclists.org/nmap-dev/2009/q1/0918.html "non-Windows boxes (Samba on Linux/OS X, or a printer)"
  -- http://www.skullsecurity.org/blog/?p=209#comment-156
  --   "That means either it isn’t a Windows machine, or the service is
  --    either crashed or not running. That may indicate a failed (or
  --    successful) exploit attempt, or just a locked down system.
  --    NT_STATUS_OBJECT_NAME_NOT_FOUND can be returned if the browser
  --    service is disabled. There are at least two ways that can happen:
  --    1) The service itself is disabled in the services list.
  --    2) The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Browser\Parameters\MaintainServerList
  --       is set to Off/False/No rather than Auto or yes.
  --    On these systems, if you reenable the browser service, then the
  --    test will complete."
  ["NT_STATUS_OBJECT_NAME_NOT_FOUND"] =
  [[UNKNOWN; not Windows, or Windows with disabled browser service (CLEAN); or Windows with crashed browser service (possibly INFECTED).
|  If you know the remote system is Windows, try rebooting it and scanning
|_ again. (Error NT_STATUS_OBJECT_NAME_NOT_FOUND)]],
  -- http://www.skullsecurity.org/blog/?p=209#comment-100
  --   "That likely means that the server has been locked down, so we
  --    don’t have access to the necessary pipe. Fortunately, that means
  --    that neither does Conficker — NT_STATUS_ACCESS_DENIED probably
  --    means you’re ok."
  ["NT_STATUS_ACCESS_DENIED"] =
  [[Likely CLEAN; access was denied.
|  If you have a login, try using --script-args=smbuser=xxx,smbpass=yyy
|  (replace xxx and yyy with your username and password). Also try
|_ smbdomain=zzz if you know the domain. (Error NT_STATUS_ACCESS_DENIED)]],
  -- The cause of these two is still unknown.
  -- ["NT_STATUS_NOT_SUPPORTED"] =
  -- [[]]
  -- http://thatsbroken.com/?cat=5 (doesn't seem common)
  -- ["NT_STATUS_REQUEST_NOT_ACCEPTED"] =
  -- [[]]
}

---Check if the server is infected with Conficker. This can be detected by a modified MS08-067 patch,
-- which rejects a different illegal string than the official patch rejects.
--
-- Based loosely on the Simple Conficker Scanner, found here:
-- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can fix it
--
--@param host The host object.
--@return (status, result) If status is false, result is an error code; otherwise, result is either
--        <code>INFECTED</code> or <code>INFECTED2</code> for infected or <code>CLEAN</code> for not infected.
function check_conficker(host)
  local status, smbstate
  local bind_result, netpathcompare_result

  -- Create the SMB session
  status, smbstate = msrpc.start_smb(host, "\\\\BROWSER", true)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to SRVSVC service
  status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  -- Try checking a valid string to find Conficker.D
  local netpathcanonicalize_result, error_result
  status, netpathcanonicalize_result, error_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\")
  if(status == true and netpathcanonicalize_result['can_path'] == 0x5c45005c) then
    msrpc.stop_smb(smbstate)
    return true, INFECTED2
  end

  -- Try checking an illegal string ("\..\") to find Conficker.C and earlier
  status, netpathcanonicalize_result, error_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\..\\")

  if(status == false) then
    if(string.find(netpathcanonicalize_result, "INVALID_NAME")) then
      msrpc.stop_smb(smbstate)
      return true, CLEAN
    elseif(string.find(netpathcanonicalize_result, "WERR_INVALID_PARAMETER") ~= nil) then
      msrpc.stop_smb(smbstate)
      return true, INFECTED
    else
      msrpc.stop_smb(smbstate)
      return false, netpathcanonicalize_result
    end
  end

  -- Stop the SMB session
  msrpc.stop_smb(smbstate)

  return true, CLEAN
end

action = function(host)

  local status, result, message
  local response = {}
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln_table = {
    title = 'Microsoft Windows system infected by Conficker',
    IDS = {CVE = '2008-4250'},
    description = [[
This system shows signs of being infected by a variant of the worm Conficker.]],
    state = vulns.STATE.NOT_VULN,
    references = {
      'http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Win32%2fConficker',
      'https://technet.microsoft.com/en-us/library/security/ms08-067.aspx',
    }
  }

  -- Check for Conficker
  status, result = check_conficker(host)
  if(status == false) then
    vuln_table.extra_info = CONFICKER_ERROR_HELP[result] or "UNKNOWN; got error " .. result
    vuln_table.state = vulns.STATE.NOT_VULN
  else
    if(result == CLEAN) then
      vuln_table.state = vulns.STATE.NOT_VULN
    elseif(result == INFECTED) then
      vuln_table.extra_info = "Likely infected by Conficker.C or lower"
      vuln_table.state = vulns.STATE.LIKELY_VULN
    elseif(result == INFECTED2) then
      vuln_table.extra_info = "Likely infected by Conficker.D or higher"
      vuln_table.state = vulns.STATE.LIKELY_VULN
    else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln_table)
end
