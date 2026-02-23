local srvloc = require "srvloc"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"
local shortport = require "shortport"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
Script uses the Service Location Protocol to discover VMwareInfrastructure (VMware ESXi) service.
Afterwards it extracts ESXi release and build number. Based on build number it verifies if the
service is patched against following vulnerabilities: CVE-2019-5544, CVE-2020-3992, CVE-2021-21974.
]]

---
-- @usage
-- nmap -sU -sV -p427 --script=vmware-svrloc-vulns <target>
-- nmap -sU -sC <target>
--
-- @output
-- PORT    STATE SERVICE REASON              VERSION
-- 427/udp open  svrloc  udp-response ttl 64 Service Location Protocol; VMware ESXi 6.7.0 (build: 17167734)
-- | vmware-svrloc-vulns:
-- |   VULNERABLE:
-- |   Heap-overflow issue in OpenSLP as used in VMware ESXi
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2021-21974
-- |     Risk factor: High  CVSS: 8.8 (HIGH)
-- |       OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551,
-- |       6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG)
-- |       has a heap-overflow vulnerability that when exploited may result
-- |       in memory corruption and a crash of slpd or in remote code execution.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21974
-- |       https://www.zerodayinitiative.com/advisories/ZDI-21-250/
-- |       https://www.zerodayinitiative.com/blog/2021/3/1/cve-2020-3992-amp-cve-2021-21974-pre-auth-remote-code-execution-in-vmware-esxi
-- |_      https://www.vmware.com/security/advisories/VMSA-2021-0002.html
--
-- @xmloutput
-- <table key="CVE-2021-21974">
-- <elem key="title">Heap-overflow issue in OpenSLP as used in VMware ESXi</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2021-21974</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSS">8.8 (HIGH)</elem>
-- </table>
-- <table key="description">
-- <elem>OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551,&#xa;6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG)&#xa;has a heap-overflow vulnerability that when exploited may result&#xa;in memory corruption and a crash of slpd or in remote code execution.&#xa;    </elem>
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21974</elem>
-- <elem>https://www.vmware.com/security/advisories/VMSA-2021-0002.html</elem>
-- <elem>https://www.zerodayinitiative.com/advisories/ZDI-21-250/</elem>
-- <elem>https://www.zerodayinitiative.com/blog/2021/3/1/cve-2020-3992-amp-cve-2021-21974-pre-auth-remote-code-execution-in-vmware-esxi</elem>
-- </table>
-- </table>
---

author = "Mariusz Ziulek, Z-Labs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "version", "safe", "vuln"}

portrule = shortport.version_port_or_service(427, "svrloc", "udp")

-- Build numbers and versions of VMware ESXi/ESX taken from:
-- https://kb.vmware.com/s/article/2143832

-------------------------------------------------------------------------------
-- RELEASE: ESXi 7.0
-------------------------------------------------------------------------------
vmware_builds_ver70 = { "15843807", "16324942", "16850804", "17119627", "17168206", "17325020", "17325551" }
-- Release 7.0 is not affected by the issue CVE-2019-5544
ver70_CVE_2019_5544_fixed_build_pos = -1
-- CVE-2020-3992 for 7.0 fixed in build number: 17119627
-- See: https://docs.vmware.com/en/VMware-vSphere/7.0/rn/vsphere-esxi-70u1a.html
-- Key in 'vmware_builds_ver67' == 8
ver70_CVE_2020_3992_fixed_build_pos = 4
-- CVE-2021-21974 for 7.0 fixed in build number: 17325551
-- See: https://www.vmware.com/security/advisories/VMSA-2021-0002.html
-- Key in 'vmware_builds_ver67' == 8
ver70_CVE_2021_21974_fixed_build_pos = 7

-------------------------------------------------------------------------------
-- RELEASE: ESXi 6.7
-------------------------------------------------------------------------------
-- builds numbers for 6.7.x releases (starting from the oldest one)
vmware_builds_ver67 = { "8169922", "8941472", "9214924", "9484548", "10176752", "10302608", "10764712", "11675023", "13004448", "13006603", "13473784", "13644319", "13981272", "14320388", "15018017", "15160138", "15820472", "16075168", "16316930", "16713306", "16773714", "17098360", "17167734", "17499825" }
-- CVE-2019-5544 for 6.7.x fixed in build number: 15160138
-- See: https://docs.vmware.com/en/VMware-vSphere/6.7/rn/esxi670-201912001.html
-- Key in 'vmware_builds_ver67' == 2
ver67_CVE_2019_5544_fixed_build_pos = 16
-- CVE-2020-3992 for 6.7.x fixed in build number: 17098360
-- See: https://docs.vmware.com/en/VMware-vSphere/6.7/rn/esxi670-202011001.html
-- Key in 'vmware_builds_ver67' == 8
ver67_CVE_2020_3992_fixed_build_pos = 22
-- CVE-2021-21974 for 6.7.x fixed in build number: 17499825
-- See: https://docs.vmware.com/en/VMware-vSphere/6.7/rn/esxi670-202102001.html
-- Key in 'vmware_builds_ver67' == 24
ver67_CVE_2021_21974_fixed_build_pos = 24

-------------------------------------------------------------------------------
-- RELEASE: ESXi 6.5
-------------------------------------------------------------------------------
-- builds numbers for 6.5.x releases (starting from the oldest one)
vmware_builds_ver65 = { "4564106", "4887370", "5146846",  "5224529", "5310538", "5969303", "6765664", "7388607", "7967591", "8294253", "8935087", "9298722",  "10175896", "10390116", "10719125", "10884925", "11925212", "13004031", "13635690", "13932383", "14320405",  "14874964", "14990892", "15177306", "15256549", "16207673", "16389870", "16576891", "16901156", "17097218", "17167537", "17477841" }
-- Table indexes of fixed versions:
-- CVE-2019-5544 for 6.5.x fixed in build number: 15177306
-- See: https://docs.vmware.com/en/VMware-vSphere/6.5/rn/esxi650-201912001.html
-- Key in 'vmware_builds_ver65' == 24
ver65_CVE_2019_5544_fixed_build_pos = 24
-- CVE-2020-3992 for 6.5.x fixed in build number: 17097218
-- See: https://docs.vmware.com/en/VMware-vSphere/6.5/rn/esxi650-202011001.html
-- Key in 'vmware_builds_ver65' == 30
ver65_CVE_2020_3992_fixed_build_pos = 30
-- CVE-2021-21974 for 6.5.x fixed in build number: 17477841
-- See: https://docs.vmware.com/en/VMware-vSphere/6.5/rn/esxi650-202102001.html
-- Key in 'vmware_builds_ver67' == 32
ver65_CVE_2021_21974_fixed_build_pos = 32

-------------------------------------------------------------------------------
-- RELEASE: ESXi 6.0
-------------------------------------------------------------------------------
-- builds numbers for 6.0.x releases (starting from the oldest one)
vmware_builds_ver60 = { "2494585", "2615704", "2715440",  "2809209", "3029758", "3073146", "3247720", "3380124", "3568940", "3620759", "3825889", "4192238",  "4510822", "4600944", "5050593", "5224934", "5251621", "5251623", "5572656", "6765062", "6921384",  "7504637", "7967664", "8934903", "9239799", "9313334", "9919195", "10474991", "10719132", "13003896", "13635687", "15018929", "14513180", "15169789", "15517548" }
-- Table indexes of fixed versions:
-- CVE-2019-5544 for 6.0.x fixed in build number: 15169789
-- See: https://docs.vmware.com/en/VMware-vSphere/6.0/rn/esxi600-201912001.html
-- Key in 'vmware_builds_ver60' == 34
ver60_CVE_2019_5544_fixed_build_pos = 34
-- Release 6.0.x is not affected by the issue CVE-2020-3992
ver60_CVE_2020_3992_fixed_build_pos = -1
-- Release 6.0.x is not affected by the issue CVE-2021-21974
ver60_CVE_2021_21974_fixed_build_pos = -1

action = function (host, port)

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local vuln_CVE_2019_5544 = {
    title = 'Heap overwrite issue in the OpenSLP as used in VMware ESXi',
    state = vulns.STATE.NOT_VULN,
    description = [[
OpenSLP as used in ESXi (6.7 before ESXi670-201912001,
6.5 before ESXi650-201912001, 6.0 before ESXi600-201912001)
has a heap overwrite vulnerability that when exploited may result
in memory corruption and a crash of slpd or in remote code execution.
    ]],
    IDS = {CVE = 'CVE-2019-5544'},
    risk_factor = "High",
    scores = {
        CVSS = "9.8 (CRITICAL)",
    },
    references = {
      'https://www.openwall.com/lists/oss-security/2019/12/06/1',
      'https://www.vmware.com/security/advisories/VMSA-2019-0022.html'
    },
  }

  local vuln_CVE_2020_3992 = {
    title = 'Use-after-free in the OpenSLP as used in VMware ESXi',
    state = vulns.STATE.NOT_VULN,
    description = [[
OpenSLP as used in VMware ESXi (7.0 before ESXi_7.0.1-0.0.16850804,
6.7 before ESXi670-202010401-SG, 6.5 before ESXi650-202010401-SG)
has a use-after-free issue.
    ]],
    IDS = {CVE = 'CVE-2020-3992'},
    risk_factor = "High",
    scores = {
        CVSS = "9.8 (CRITICAL)",
    },
    references = {
      'https://www.zerodayinitiative.com/advisories/ZDI-20-1377/',
      'https://www.zerodayinitiative.com/advisories/ZDI-20-1385/',
      'https://www.vmware.com/security/advisories/VMSA-2020-0023.html',
      'https://www.zerodayinitiative.com/blog/2021/3/1/cve-2020-3992-amp-cve-2021-21974-pre-auth-remote-code-execution-in-vmware-esxi'
    },
  }

  local vuln_CVE_2021_21974 = {
    title = 'Heap-overflow issue in OpenSLP as used in VMware ESXi',
    state = vulns.STATE.NOT_VULN,
    description = [[
OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551,
6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG)
has a heap-overflow vulnerability that when exploited may result
in memory corruption and a crash of slpd or in remote code execution.
    ]],
    IDS = {CVE = 'CVE-2021-21974'},
    risk_factor = "High",
    scores = {
        CVSS = "8.8 (HIGH)",
    },
    references = {
      'https://www.vmware.com/security/advisories/VMSA-2021-0002.html',
      'https://www.zerodayinitiative.com/advisories/ZDI-21-250/',
      'https://www.zerodayinitiative.com/blog/2021/3/1/cve-2020-3992-amp-cve-2021-21974-pre-auth-remote-code-execution-in-vmware-esxi'
    },
  }

  local helper = srvloc.Helper:new(host)

  -- query for VMwareInfrastructure service
  local status, res = helper:ServiceRequest("service:VMwareInfrastructure", "DEFAULT")
  if ( not(status) or not(res) ) then
    helper:close()
    stdnse.debug1("Not a VMware service. Skipping.")
    return
  end
  res = res[1]

  stdnse.debug1("'SrvRply' received. Sending 'AttrRqst' message with 'product' tag.")

  -- request for attributes. Query only for 'product' attribute to get ESXi build version
  local status, prod_attrib = helper:AttributeRequest(res, "DEFAULT", "product")
  helper:close()
  if ( not(status) or not(prod_attrib) ) then
    stdnse.debug1("No 'product' tag received. Skipping.")
    return
  end

  -- extract VMware version and build number keep it in current_{version,build} vars
  local ver_build_str = prod_attrib:match("^%(product=\"VMware ESXi (.*)\"%)$")
  if ( not(ver_build_str) ) then
    stdnse.debug1("Unrecognized structure of 'product' attribute. Skipping.")
    return
  end

  stdnse.debug1("VMware version: '" .. ver_build_str .. "'")

  local a = stringaux.strsplit(" ", ver_build_str)
  if ( not(a) ) then
    stdnse.debug1("Could not extract ESXi version and build name. Skipping.")
    return
  end

  local current_version = a[1]
  local current_build = a[2]:match("^build%-(.*)$")
  if ( not(current_build) ) then
    stdnse.debug1("Could not extract ESXi build name. Skipping.")
    return
  end

  -- use appropriate build number lookup table (based on ESXi version number)
  local vmware_builds
  if current_version:find("6.0") then
    vmware_builds = vmware_builds_ver60
    CVE_2019_5544_index = ver60_CVE_2019_5544_fixed_build_pos
    CVE_2020_3992_index = ver60_CVE_2020_3992_fixed_build_pos
    CVE_2021_21974_index = ver60_CVE_2021_21974_fixed_build_pos
  elseif current_version:find("6.5") then
    vmware_builds = vmware_builds_ver65
    CVE_2019_5544_index = ver65_CVE_2019_5544_fixed_build_pos
    CVE_2020_3992_index = ver65_CVE_2020_3992_fixed_build_pos
    CVE_2021_21974_index = ver65_CVE_2021_21974_fixed_build_pos
  elseif current_version:find("6.7") then
    vmware_builds = vmware_builds_ver67
    CVE_2019_5544_index = ver67_CVE_2019_5544_fixed_build_pos
    CVE_2020_3992_index = ver67_CVE_2020_3992_fixed_build_pos
    CVE_2021_21974_index = ver67_CVE_2021_21974_fixed_build_pos
  elseif current_version:find("7.0") then
    vmware_builds = vmware_builds_ver70
    CVE_2019_5544_index = ver70_CVE_2019_5544_fixed_build_pos
    CVE_2020_3992_index = ver70_CVE_2020_3992_fixed_build_pos
    CVE_2021_21974_index = ver70_CVE_2021_21974_fixed_build_pos
  end

  -- iterate thru VMware build number table and determine 'position' of the current build
  local current_position
  for key, value in pairs(vmware_builds) do
    if value == current_build then
      current_position = key
      break
    end
  end

  if ( not(current_position) ) then
    stdnse.debug1("Build number '" .. current_build .. "' is newer than affected build numbers. Skipping.")
    return
  end 

  -- determine if a given instance of VMware is affected by the CVE-2019-5544/CVE-2020-3992/CVE-2021-21974
  -- i.e. verify if the current build number is older than the builds that have provided fixes
  if CVE_2019_5544_index ~= -1 and current_position < CVE_2019_5544_index then
    stdnse.debug("Build VULNERABLE to CVE-2019-5544 issue.")
    vuln_CVE_2019_5544.state = vulns.STATE.VULN
  end

  if CVE_2020_3992_index ~= -1 and current_position < CVE_2020_3992_index then
    stdnse.debug("Build VULNERABLE to CVE-2020-3992 issue.")
    vuln_CVE_2020_3992.state = vulns.STATE.VULN
  end

  if CVE_2021_21974_index ~= -1 and current_position < CVE_2021_21974_index then
    stdnse.debug("Build VULNERABLE to CVE-2021-21974 issue.")
    vuln_CVE_2021_21974.state = vulns.STATE.VULN
  end

  if port.version.product and current_version and current_build then
    port.version.version = ""
    port.version.product = ("%s; VMware ESXi %s (build: %s)"):format(port.version.product, current_version, current_build)
    nmap.set_port_version(host, port)
  end

  vuln_report:add_vulns(vuln_CVE_2019_5544)
  vuln_report:add_vulns(vuln_CVE_2020_3992)
  vuln_report:add_vulns(vuln_CVE_2021_21974)
  return vuln_report:make_output()
end
