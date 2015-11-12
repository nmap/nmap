local anyconnect = require('anyconnect')
local shortport = require('shortport')
local vulns = require('vulns')
local sslcert = require('sslcert')
local stdnse = require "stdnse"

description = [[
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP
Denial of Service Vulnerability (CVE-2014-2129).
]]

---
-- @usage
-- nmap -p 443 --script http-vuln-cve2014-2127 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-cve2014-2129:
-- |   VULNERABLE:
-- |   Cisco ASA SIP Denial of Service Vulnerability
-- |     State: VULNERABLE
-- |     Risk factor: High  CVSSv2: 7.1 (HIGH) (AV:N/AC:M/AU:N/C:N/I:N/A:C)
-- |     Description:
-- |       The SIP inspection engine in Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.48), 8.4 before 8.4(6.5), 9.0 before 9.0(3.1), and 9.1 before 9.1(2.5) allows remote attackers to cause a denial of service (memory consumption or device reload) via crafted SIP packets, aka Bug ID CSCuh44052.
-- |
-- |     References:
-- |       http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa
-- |_      http://cvedetails.com/cve/2014-2129/

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

action = function(host, port)
  local vuln_table = {
    title = "Cisco ASA SIP Denial of Service Vulnerability",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    scores = {
      CVSSv2 = "7.1 (HIGH) (AV:N/AC:M/AU:N/C:N/I:N/A:C)",
    },
    description = [[
The SIP inspection engine in Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.48), 8.4 before 8.4(6.5), 9.0 before 9.0(3.1), and 9.1 before 9.1(2.5) allows remote attackers to cause a denial of service (memory consumption or device reload) via crafted SIP packets, aka Bug ID CSCuh44052.
    ]],

    references = {
      'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa',
      'http://cvedetails.com/cve/2014-2129/'
    }
  }

  local vuln_versions = {
    ['8'] = {
      ['2'] = 5.48,
      ['4'] = 6.5,
    },
    ['9'] = {
      ['0'] = 3.1,
      ['1'] = 2.5,
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
