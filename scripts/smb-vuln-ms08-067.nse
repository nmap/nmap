local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects Microsoft Windows systems vulnerable to the remote code execution vulnerability
known as MS08-067. This check is dangerous and it may crash systems.

On a fairly wide scan conducted by Brandon Enright, we determined
that on average, a vulnerable system is more likely to crash than to survive
the check. Out of 82 vulnerable systems, 52 crashed.
Please consider this before running the script.

This check was previously part of smb-check-vulns.nse.
]]
---
--@usage
-- nmap --script smb-vuln-ms08-067.nse -p445 <host>
-- nmap -sU --script smb-vuln-ms08-067.nse -p U:137 <host>
--
--@output
--| smb-vuln-ms08-067:
--|   VULNERABLE:
--|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
--|     State: VULNERABLE
--|     IDs:  CVE:CVE-2008-4250
--|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
--|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
--|           code via a crafted RPC request that triggers the overflow during path canonicalization.
--|
--|     Disclosure date: 2008-10-23
--|     References:
--|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
--|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
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
local UNKNOWN    = 3
local NOTRUN     = 4
local INFECTED   = 5

---Check if the server is patched for MS08-067. This is done by calling NetPathCompare with an
-- illegal string. If the string is accepted, then the server is vulnerable; if it's rejected, then
-- you're safe (for now).
--
-- Based on a packet cap of this script, thanks go out to the author:
-- http://labs.portcullis.co.uk/application/ms08-067-check/
--
-- NOTE: This CAN crash stuff (ie, crash svchost and force a reboot), so beware! In about 20
-- tests I did, it crashed once. This is not a guarantee.
--
--@param host The host object.
--@return (status, result) If status is false, result is an error code; otherwise, result is either
--        <code>VULNERABLE</code> for vulnerable, <code>PATCHED</code> for not vulnerable,
--        <code>UNKNOWN</code> if there was an error (likely vulnerable),
--        and <code>INFECTED</code> if it was patched by Conficker.
function check_ms08_067(host)
  local status, smbstate
  local bind_result, netpathcompare_result

  -- Create the SMB session
  status, smbstate = msrpc.start_smb(host, "\\\\BROWSER")
  if(status == false) then
    return false, smbstate
  end

  -- Bind to SRVSVC service
  status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  -- Call netpathcanonicalize
  -- status, netpathcanonicalize_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\a", "\\test\\")

  local path1 = "\\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\..\\n"
  local path2 = "\\n"
  status, netpathcompare_result = msrpc.srvsvc_netpathcompare(smbstate, host.ip, path1, path2, 1, 0)

  -- Stop the SMB session
  msrpc.stop_smb(smbstate)

  if(status == false) then
    if(string.find(netpathcompare_result, "WERR_INVALID_PARAMETER") ~= nil) then
      return true, INFECTED
    elseif(string.find(netpathcompare_result, "INVALID_NAME") ~= nil) then
      return true, PATCHED
    else
      return true, UNKNOWN, netpathcompare_result
    end
  end

  return true, VULNERABLE
end

action = function(host)
  local status, result, message
  local response = {}
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln_table = {
    title = 'Microsoft Windows system vulnerable to remote code execution (MS08-067)',
    state = vulns.STATE.NOT_VULN,
    description = [[
    The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
    Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
    code via a crafted RPC request that triggers the overflow during path canonicalization.
    ]],
    IDS = {CVE = 'CVE-2008-4250'},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms08-067.aspx'
    },
    dates = {
      disclosure = {year = '2008', month = '10', day = '23'},
    }
  }
  -- Check for ms08-067
  status, result, message = check_ms08_067(host)
  if(status == false) then
    vuln_table.state = vulns.STATE.NOT_VULN
  else
    if(result == VULNERABLE) then
      vuln_table.state = vulns.STATE.VULN
    elseif(result == UNKNOWN) then
      vuln_table.state = vulns.STATE.LIKELY_VULN
   elseif(result == INFECTED) then
      vuln_table.exploit_results = "This system has been infected by the Conficker worm."
      vuln_table.state = vulns.STATE.LIKELY_VULN
    else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln_table)
end
