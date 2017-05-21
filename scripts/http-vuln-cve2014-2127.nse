local anyconnect = require('anyconnect')
local shortport = require('shortport')
local vulns = require('vulns')
local sslcert = require('sslcert')
local stdnse = require "stdnse"

description = [[
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN
Privilege Escalation Vulnerability (CVE-2014-2127).
]]

---
-- @see http-vuln-cve2014-2126.nse
-- @see http-vuln-cve2014-2128.nse
-- @see http-vuln-cve2014-2129.nse
--
-- @usage
-- nmap -p 443 --script http-vuln-cve2014-2127 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-cve2014-2127:
-- |   VULNERABLE:
-- |   Cisco ASA SSL VPN Privilege Escalation Vulnerability
-- |     State: VULNERABLE
-- |     Risk factor: High  CVSSv2: 8.5 (HIGH) (AV:N/AC:M/AU:S/C:C/I:C/A:C)
-- |     Description:
-- |       Cisco Adaptive Security Appliance (ASA) Software 8.x before 8.2(5.48), 8.3 before 8.3(2.40), 8.4 before 8.4(7.9), 8.6 before 8.6(1.13), 9.0 before 9.0(4.1), and 9.1 before 9.1(4.3) does not properly process management-session information during privilege validation for SSL VPN portal connections, which allows remote authenticated users to gain privileges by establishing a Clientless SSL VPN session and entering crafted URLs, aka Bug ID CSCul70099.
-- |
-- |     References:
-- |       http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa
-- |_      http://cvedetails.com/cve/2014-2127/

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

action = function(host, port)
  local vuln_table = {
    title = "Cisco ASA SSL VPN Privilege Escalation Vulnerability",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    scores = {
      CVSSv2 = "8.5 (HIGH) (AV:N/AC:M/AU:S/C:C/I:C/A:C)",
    },
    description = [[
Cisco Adaptive Security Appliance (ASA) Software 8.x before 8.2(5.48), 8.3 before 8.3(2.40), 8.4 before 8.4(7.9), 8.6 before 8.6(1.13), 9.0 before 9.0(4.1), and 9.1 before 9.1(4.3) does not properly process management-session information during privilege validation for SSL VPN portal connections, which allows remote authenticated users to gain privileges by establishing a Clientless SSL VPN session and entering crafted URLs, aka Bug ID CSCul70099.
    ]],

    references = {
      'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa',
      'http://cvedetails.com/cve/2014-2127/'
    }
  }

  local vuln_versions = {
    ['8'] = {
      ['2'] = 5.48,
      ['3'] = 2.40,
      ['4'] = 7.9,
      ['6'] = 1.13,
    },
    ['9'] = {
      ['0'] = 4.1,
      ['1'] = 4.3,
    },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local ac = anyconnect.Cisco.AnyConnect:new(host, port)
  local status, err = ac:connect()
  if not status then
    return stdnse.format_output(false, err)
  else
    local ver = ac:get_version()
    if vuln_versions[ver['major']] and vuln_versions[ver['major']][ver['minor']] then
      if vuln_versions[ver['major']][ver['minor']] > tonumber(ver['rev']) then
        vuln_table.state = vulns.STATE.VULN
      end
    end
  end
  return report:make_output(vuln_table)
end
