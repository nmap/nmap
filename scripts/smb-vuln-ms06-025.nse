local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"
local rand = require "rand"

description = [[
Detects Microsoft Windows systems with Ras RPC service vulnerable to MS06-025.

MS06-025 targets the <code>RasRpcSumbitRequest()</code> RPC method which is
a part of RASRPC interface that serves as a RPC service for configuring and
getting information from the Remote Access and Routing service. RASRPC can be
accessed using either "\ROUTER" SMB pipe or the "\SRVSVC" SMB pipe (usually on Windows XP machines).
This is in RPC world known as "ncan_np" RPC transport. <code>RasRpcSumbitRequest()</code>
method is a generic method which provides different functionalities according
to the <code>RequestBuffer</code> structure and particularly the <code>RegType</code> field within that
structure. <code>RegType</code> field is of <code>enum ReqTypes</code> type. This enum type lists all
the different available operation that can be performed using the <code>RasRpcSubmitRequest()</code>
RPC method. The one particular operation that this vuln targets is the <code>REQTYPE_GETDEVCONFIG</code>
request to get device information on the RRAS.

This script was previously part of smb-check-vulns.
]]
---
--@usage
-- nmap --script smb-vuln-ms06-025.nse -p445 <host>
-- nmap -sU --script smb-vuln-ms06-025.nse -p U:137,T:139 <host>
--
--@output
--| smb-vuln-ms06-025:
--|   VULNERABLE:
--|   RRAS Memory Corruption vulnerability (MS06-025)
--|     State: VULNERABLE
--|     IDs:  CVE:CVE-2006-2370
--|           A buffer overflow vulnerability in the Routing and Remote Access service (RRAS) in Microsoft Windows 2000 SP4, XP SP1
--|           and SP2, and Server 2003 SP1 and earlier allows remote unauthenticated or authenticated attackers to
--|           execute arbitrary code via certain crafted "RPC related requests" aka the "RRAS Memory Corruption Vulnerability."
--|
--|     Disclosure date: 2006-6-27
--|     References:
--|       https://technet.microsoft.com/en-us/library/security/ms06-025.aspx
--|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2370
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
local NOTUP      = 8

---Check the existence of ms06_025 vulnerability in Microsoft Remote Routing
--and Access Service. This check is not safe as it crashes the RRAS service and
--its dependencies.
--@param host Host object.
--@return (status, result)
--* <code>status == false</code> -> <code>result == NOTUP</code> which designates
--that the targeted Ras RPC service is not active.
--* <code>status == true</code> ->
-- ** <code>result == VULNERABLE</code> for vulnerable.
-- ** <code>result == PATCHED</code> for not vulnerable.
function check_ms06_025(host)
  --create the SMB session
  --first we try with the "\router" pipe, then the "\srvsvc" pipe.
  local status, smb_result, smbstate, err_msg
  status, smb_result = msrpc.start_smb(host, msrpc.ROUTER_PATH)
  if(status == false) then
    err_msg = smb_result
    status, smb_result = msrpc.start_smb(host, msrpc.SRVSVC_PATH) --rras is also accessible across SRVSVC pipe
    if(status == false) then
      return false, NOTUP --if not accessible across both pipes then service is inactive
    end
  end
  smbstate = smb_result
  --bind to RRAS service
  local bind_result
  status, bind_result = msrpc.bind(smbstate, msrpc.RASRPC_UUID, msrpc.RASRPC_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, UNKNOWN --if bind operation results with a false status we can't conclude anything.
  end
  if(bind_result['ack_result'] == 0x02) then --0x02 == PROVIDER_REJECTION
    msrpc.stop_smb(smbstate)
    return false, NOTUP --if bind operation results with true but PROVIDER_REJECTION, then the service is inactive.
  end
  local req, buff, sr_result
  req = msrpc.RRAS_marshall_RequestBuffer(
    0x01,
    msrpc.RRAS_RegTypes['GETDEVCONFIG'],
    rand.random_string(3000, "0123456789abcdefghijklmnoprstuvzxwyABCDEFGHIJKLMNOPRSTUVZXWY"))
  status, sr_result = msrpc.RRAS_SubmitRequest(smbstate, req)
  msrpc.stop_smb(smbstate)
  --sanity check
  if(status == false) then
    stdnse.debug3("check_ms06_025: RRAS_SubmitRequest failed")
    if(sr_result == "NT_STATUS_PIPE_BROKEN") then
      return true, VULNERABLE
    else
      return true, PATCHED
    end
  else
    return true, PATCHED
  end
end

action = function(host)
  local status, result, message
  local response = {}
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host)
  local vuln_table = {
    title = 'RRAS Memory Corruption vulnerability (MS06-025)',
    state = vulns.STATE.NOT_VULN,
    description = [[
    A buffer overflow vulnerability in the Routing and Remote Access service (RRAS) in Microsoft Windows 2000 SP4, XP SP1
    and SP2, and Server 2003 SP1 and earlier allows remote unauthenticated or authenticated attackers to
    execute arbitrary code via certain crafted "RPC related requests" aka the "RRAS Memory Corruption Vulnerability."
    ]],
    IDS = {CVE = 'CVE-2006-2370'},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms06-025.aspx'
    },
    dates = {
      disclosure = {year = '2006', month = '6', day = '27'},
    }
  }

  -- Check for ms06-025
  status, result = check_ms06_025(host)
  if(status == false) then
    if(result == NOTUP) then
      vuln_table.extra_info = "Ras RPC service is not enabled."
      vuln_table.state = vulns.STATE.NOT_VULN
    else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  else
    if(result == VULNERABLE) then
      vuln_table.state = vulns.STATE.VULN
    elseif(result == NOTUP) then
      vuln_table.extra_info = "Ras RPC service is not enabled."
      vuln_table.state = vulns.STATE.NOT_VULN
   else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln_table)
end
