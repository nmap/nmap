local anyconnect = require('anyconnect')
local shortport = require('shortport')
local vulns = require('vulns')
local sslcert = require('sslcert')
local stdnse = require "stdnse"

description = [[
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN
Authentication Bypass Vulnerability (CVE-2014-2128).
]]

---
-- @see http-vuln-cve2014-2126.nse
-- @see http-vuln-cve2014-2127.nse
-- @see http-vuln-cve2014-2129.nse
--
-- @usage
-- nmap -p 443 --script http-vuln-cve2014-2128 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-cve2014-2128:
-- |   VULNERABLE:
-- |   Cisco ASA SSL VPN Authentication Bypass Vulnerability
-- |     State: VULNERABLE
-- |     Risk factor: Medium  CVSSv2: 5.0 (MEDIUM) (AV:N/AC:L/AU:N/C:P/I:N/A:N)
-- |     Description:
-- |       The SSL VPN implementation in Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.47, 8.3 before 8.3(2.40), 8.4 before 8.4(7.3), 8.6 before 8.6(1.13), 9.0 before 9.0(3.8), and 9.1 before 9.1(3.2) allows remote attackers to bypass authentication via (1) a crafted cookie value within modified HTTP POST data or (2) a crafted URL, aka Bug ID CSCua85555.
-- |
-- |     References:
-- |       http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa
-- |_      http://cvedetails.com/cve/2014-2128/

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

action = function(host, port)
  local vuln_table = {
    title = "Cisco ASA SSL VPN Authentication Bypass Vulnerability",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "Medium",
    scores = {
      CVSSv2 = "5.0 (MEDIUM) (AV:N/AC:L/AU:N/C:P/I:N/A:N)",
    },
    description = [[
The SSL VPN implementation in Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.47, 8.3 before 8.3(2.40), 8.4 before 8.4(7.3), 8.6 before 8.6(1.13), 9.0 before 9.0(3.8), and 9.1 before 9.1(3.2) allows remote attackers to bypass authentication via (1) a crafted cookie value within modified HTTP POST data or (2) a crafted URL, aka Bug ID CSCua85555.
    ]],

    references = {
      'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa',
      'http://cvedetails.com/cve/2014-2128/'
    }
  }

  local vuln_versions = {
    ['8'] = {
      ['2'] = 5.47,
      ['3'] = 2.40,
      ['4'] = 7.3,
      ['6'] = 1.13,
      ['7'] = 1.11,
    },
    ['9'] = {
      ['0'] = 3.8,
      ['1'] = 3.2,
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
