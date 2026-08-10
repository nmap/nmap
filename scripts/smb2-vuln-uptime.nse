local os = require "os"
local datetime = require "datetime"
local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"
local smb2 = require "smb2"
local table = require "table"

description = [[
Attempts to detect missing patches in Windows systems by checking the
uptime returned during the SMB2 protocol negotiation.

SMB2 protocol negotiation response returns the system boot time
 pre-authentication. This information can be used to determine
 if a system is missing critical patches without triggering IDS/IPS/AVs.

Remember that a rebooted system may still be vulnerable. This check
only reveals unpatched systems based on the uptime, no additional probes are sent.

References:
* https://twitter.com/breakersall/status/880496571581857793
]]

---
-- @usage nmap -O --script smb2-vuln-uptime <target>
-- @usage nmap -p445 --script smb2-vuln-uptime --script-args smb2-vuln-uptime.skip-os=true <target>
--
-- @output
-- | smb2-vuln-uptime:
-- |   VULNERABLE:
-- |   MS17-010: Security update for Windows SMB Server
-- |     State: LIKELY VULNERABLE
-- |     IDs:  ms:ms17-010  CVE:2017-0147
-- |       This system is missing a security update that resolves vulnerabilities in
-- |        Microsoft Windows SMB Server.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=2017-0147
-- |_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
--
-- @xmloutput
-- <table key="2017-0147">
-- <elem key="title">MS17-010: Security update for Windows SMB Server</elem>
-- <elem key="state">LIKELY VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:2017-0147</elem>
-- <elem>ms:ms17-010</elem>
-- </table>
-- <table key="description">
-- <elem>This system is missing a security update that resolves vulnerabilities in&#xa; Microsoft Windows SMB Server.&#xa;</elem>
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=2017-0147</elem>
-- <elem>https://technet.microsoft.com/en-us/library/security/ms17-010.aspx</elem>
-- </table>
-- </table>
--
-- @args smb2-vuln-uptime.skip-os Ignore OS detection results and show results
---

author = "Paulino Calderon <calderon()calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

hostrule = function(host)
  local ms = false
  local os_detection = stdnse.get_script_args(SCRIPT_NAME .. ".skip-os") or false
  if host.os then
    for k, v in pairs(host.os) do -- Loop through OS matches
      if string.match(v['name'], "Microsoft") then
        ms = true
      end
    end
  end
  return (smb.get_port(host) ~= nil and ms) or (os_detection)
end

local ms_vulns = {
  {
    title = 'MS17-010: Security update for Windows SMB Server',
    ids = {ms = "ms17-010", CVE = "2017-0147"},
    desc = [[
This system is missing a security update that resolves vulnerabilities in
 Microsoft Windows SMB Server.
]],
    disclosure_time = 1489471200,
    disclosure_date = {year=2017, month=3, day=14},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx',
    },
  },
  {
    title = 'Microsoft Kerberos Checksum Vulnerability',
    ids = {ms = "ms14-068", CVE = "2014-6324"},
    desc = [[
This security update resolves a privately reported vulnerability in Microsoft
 Windows Kerberos KDC that could allow an attacker to elevate unprivileged
 domain user account privileges to those of the domain administrator account.
]],
    disclosure_time = 1416290400,
    disclosure_date = {year=2014, month=11, day=18},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms14-068.aspx'
    },
  },
}

local function check_vulns(host, port)
  local smbstate, status
  local vulns_detected = {}

  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate)

  if not status then
    stdnse.debug2("Negotiation failed")
    return nil, "Protocol negotiation failed (SMB2)"
  end

  datetime.record_skew(host, smbstate.time, os.time())
  stdnse.debug2("SMB2: Date: %s (%s) Start date:%s (%s)",
                      smbstate['date'], smbstate['time'],
          smbstate['start_date'], smbstate['start_time'])
  if smbstate['start_time'] == 0 then
    stdnse.debug2("Boot time not provided")
    return nil, "Boot time not provided"
  end

  for _, vuln in pairs(ms_vulns) do
    if smbstate['start_time'] < vuln['disclosure_time'] then
      stdnse.debug2("Vulnerability detected")
      vuln.extra_info = string.format("The system hasn't been rebooted since %s", smbstate['start_date'])
      table.insert(vulns_detected, vuln)
    end
  end

  return true, vulns_detected
end

action = function(host,port)
  local status, vulnerabilities
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  status, vulnerabilities = check_vulns(host, port)
  if status then
    for i, v in pairs(vulnerabilities) do
      local vuln = { title = v['title'], description = v['desc'],
            references = v['references'], disclosure_date = v['disclosure_date'],
            IDS = v['ids']}
      vuln.state = vulns.STATE.LIKELY_VULN
      vuln.extra_info = v['extra_info']
      report:add_vulns(SCRIPT_NAME, vuln)
    end
  end
  return report:make_output()
end
