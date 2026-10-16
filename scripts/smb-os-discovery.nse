local nmap = require "nmap"
local smb = require "smb"
local smb2 = require "smb2"
local smbauth = require "smbauth"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"
local datetime = require "datetime"

description = [[
Attempts to determine the operating system, computer name, domain, workgroup, and current
time over the SMB protocol (ports 445 or 139).
This is done by starting a session with the anonymous
account (or with a proper user account, if one is given; it likely doesn't make
a difference); in response to a session starting, the server will send back all this
information.

The following fields may be included in the output, depending on the
circumstances (e.g. the workgroup name is mutually exclusive with domain and forest
names) and the information available:
* OS
* Computer name
* Domain name
* Forest name
* FQDN
* NetBIOS computer name
* NetBIOS domain name
* Workgroup
* System time

Some systems, like Samba, will blank out their name (and only send their domain).
Other systems (like embedded printers) will simply leave out the information. Other
systems will blank out various pieces (some will send back 0 for the current
time, for example).

Windows 10 (build 1607+) and later blank out the OS strings carried by SMB1, and
many modern hosts disable SMB1 entirely. When SMB1 information is missing, this
script falls back to a pure SMB2 session (NEGOTIATE + null-session SETUP) and
reads the OS version, build number, NetBIOS/DNS names and timestamp from the
NTLMSSP challenge. The SMB dialect in use is shown as "SMB dialect".

If this script is used in conjunction with version detection it can augment the
standard nmap version detection information with data that this script has discovered.

Retrieving the name and operating system of a server is a vital step in targeting
an attack against it, and this script makes that retrieval easy. Additionally, if
a penetration tester is choosing between multiple targets, the time can help identify
servers that are being poorly maintained (for more information/random thoughts on
using the time, see http://www.skullsecurity.org/blog/?p=76.

Although the standard <code>smb*</code> script arguments can be used,
they likely won't change the outcome in any meaningful way. However, <code>smbnoguest</code>
will speed up the script on targets that do not allow guest access.
]]

---
--@usage
-- nmap --script smb-os-discovery.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
--
--@output
-- Host script results:
-- | smb-os-discovery:
-- |   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
-- |   OS CPE: cpe:/o:microsoft:windows_2008::sp1
-- |   Computer name: Sql2008
-- |   NetBIOS computer name: SQL2008
-- |   Domain name: lab.test.local
-- |   Forest name: test.local
-- |   FQDN: Sql2008.lab.test.local
-- |   NetBIOS domain name: LAB
-- |_  System time: 2011-04-20T13:34:06-05:00
--
-- On an SMB2-only host (SMB1 disabled), output looks like:
-- | smb-os-discovery:
-- |   OS: Windows 11 23H2 (build 22631)
-- |   OS CPE: cpe:/o:microsoft:windows_11::-
-- |   SMB dialect: SMB 3.1.1
-- |   Computer name: DESKTOP-ABC
-- |   Workgroup: WORKGROUP
-- |_  System time: 2024-02-15T13:42:29+00:00
--
--@xmloutput
-- <elem key="os">Windows Server (R) 2008 Standard 6001 Service Pack 1</elem>
-- <elem key="cpe">cpe:/o:microsoft:windows_2008::sp1</elem>
-- <elem key="lanmanager">Windows Server (R) 2008 Standard 6.0</elem>
-- <elem key="domain">LAB</elem>
-- <elem key="server">SQL2008</elem>
-- <elem key="date">2011-04-20T13:34:06-05:00</elem>
-- <elem key="fqdn">Sql2008.lab.test.local</elem>
-- <elem key="domain_dns">lab.test.local</elem>
-- <elem key="forest_dns">test.local</elem>

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"smb-brute"}


--- Check whether or not this script should be run.
hostrule = function(host)
  return smb.get_port(host) ~= nil
end

-- Some observed OS strings:
--   "Windows 5.0" (is Windows 2000)
--   "Windows 5.1" (is Windows XP)
--   "Windows Server 2003 3790 Service Pack 2"
--   "Windows Vista (TM) Ultimate 6000"
--   "Windows Server (R) 2008 Standard 6001 Service Pack 1"
--   "Windows 7 Professional 7601 Service Pack 1"
-- http://msdn.microsoft.com/en-us/library/cc246806%28v=prot.20%29.aspx has a
-- list of strings that don't quite match these.
function make_cpe(result)
  local os = result.os
  local parts = {}

  if os and #os > 0 then
    if string.match(os, "^Windows 5%.0") then
      parts = {"o", "microsoft", "windows_2000"}
    elseif string.match(os, "^Windows 5%.1") then
      parts = {"o", "microsoft", "windows_xp"}
    elseif string.match(os, "^Windows Server.*2003") then
      parts = {"o", "microsoft", "windows_server_2003"}
    elseif string.match(os, "^Windows Vista") then
      parts = {"o", "microsoft", "windows_vista"}
    elseif string.match(os, "^Windows Server.*2008") then
      parts = {"o", "microsoft", "windows_server_2008"}
    elseif string.match(os, "^Windows 7") then
      parts = {"o", "microsoft", "windows_7"}
    elseif string.match(os, "^Windows 8%f[^%d.]") then
      parts = {"o", "microsoft", "windows_8"}
    elseif string.match(os, "^Windows 8.1") then
      parts = {"o", "microsoft", "windows_8.1"}
    elseif string.match(os, "^Windows 10%f[^%d.]") then
      parts = {"o", "microsoft", "windows_10"}
    elseif string.match(os, "^Windows Server.*2012") then
      parts = {"o", "microsoft", "windows_server_2012"}
    end
  end
  if #parts == 0 and result.os_major_version == 10 and result.os_minor_version == 0
    and result.os_build and result.os_build > 0 then
    -- No usable OS string (modern hosts blank it out, or pure SMB2), so fall
    -- back to the build number reported by the NTLMSSP Version field. Note
    -- that some builds are shared between client and server SKUs; where that
    -- is the case we assume the client variant.
    local build = result.os_build
    if build == 20348 or build == 25398 then
      parts = {"o", "microsoft", "windows_server_2022"}
    elseif build >= 22000 then
      parts = {"o", "microsoft", "windows_11"}
    else
      parts = {"o", "microsoft", "windows_10"}
    end
  end

  if parts[1] == "o" and parts[2] == "microsoft"
    and string.match(parts[3], "^windows") then
    parts[4] = ""
    local sp = os and string.match(os, "Service Pack (%d+)")
    if sp then
      parts[5] = "sp" .. tostring(sp)
    else
      parts[5] = "-"
    end
    if os and string.match(os, "Professional") then
      parts[6] = "professional"
    end
  end

  if #parts > 0 then
    return "cpe:/" .. table.concat(parts, ":")
  end
end

function add_to_output(output_table, label, value)
  if value then
    table.insert(output_table, string.format("%s: %s", label, value))
  end
end

-- Map NTLMSSP Version build numbers to marketing names. Windows 10 and
-- Server share build numbers in some cases; the server variants are listed
-- where they are unambiguous. Unknown builds fall back to a family name.
local build_names = {
  [10240] = "Windows 10 1507",
  [14393] = "Windows 10 1607 / Server 2016",
  [15063] = "Windows 10 1703",
  [16299] = "Windows 10 1709",
  [17134] = "Windows 10 1803",
  [17763] = "Windows 10 1809 / Server 2019",
  [18362] = "Windows 10 1903",
  [18363] = "Windows 10 1909",
  [19041] = "Windows 10 2004",
  [19042] = "Windows 10 20H2",
  [19043] = "Windows 10 21H1",
  [19044] = "Windows 10 21H2",
  [19045] = "Windows 10 22H2",
  [20348] = "Windows Server 2022",
  [25398] = "Windows Server 2022 23H2",
  [22000] = "Windows 11 21H2",
  [22621] = "Windows 11 22H2",
  [22631] = "Windows 11 23H2",
  [26100] = "Windows 11 24H2 / Server 2025",
}

function friendly_windows_name(major, minor, build)
  if major == nil or minor == nil then return nil end
  if major == 10 and minor == 0 then
    if build then
      if build_names[build] then
        return build_names[build]
      elseif build >= 22000 and build < 26100 then
        return "Windows 11"
      elseif build >= 26100 then
        return "Windows 11 / Server 2025"
      elseif build >= 10240 then
        return "Windows 10 / Server 2016+"
      end
    end
    return "Windows 10 or Server 2016+"
  elseif major == 6 and minor == 3 then
    return "Windows 8.1 / Server 2012 R2"
  elseif major == 6 and minor == 2 then
    return "Windows 8 / Server 2012"
  elseif major == 6 and minor == 1 then
    return "Windows 7 / Server 2008 R2"
  elseif major == 6 and minor == 0 then
    return "Windows Vista / Server 2008"
  elseif major == 5 and minor == 2 then
    return "Windows XP / Server 2003"
  elseif major == 5 and minor == 1 then
    return "Windows XP"
  elseif major == 5 and minor == 0 then
    return "Windows 2000"
  end
  return nil
end

--- Collect OS information over a pure SMB2 session (no SMB1, no NetBIOS).
--- Works on hosts where SMB1 is disabled entirely. Reads the OS version and
--- build from the NTLMSSP CHALLENGE Version field and the computer/domain
--- names from the challenge TargetInfo AV pairs.
local function get_os_over_smb2(host)
  local status, smbstate = smb2.start(host)
  if not status then
    stdnse.debug1("SMB2 connect/negotiate failed: %s", tostring(smbstate))
    return nil
  end
  local dialect_name = smb2.dialect_name(smbstate['dialect'])

  local status2, blob = smb2.session_setup_ntlmssp(smbstate)
  if not status2 then
    stdnse.debug1("SMB2 session setup failed: %s", tostring(blob))
    smb2.stop(smbstate)
    return nil
  end

  local info = smbauth.get_host_info_from_security_blob(blob)
  local port = smbstate['port']
  smb2.stop(smbstate)

  if type(info) ~= "table" then
    stdnse.debug1("SMB2: could not parse NTLMSSP challenge")
    return nil
  end

  info.dialect = dialect_name
  info.port = port
  if info.timestamp and info.timestamp > 0 then
    info.time = (info.timestamp // 10000000) - 11644473600
  end
  return info
end

action = function(host)
  local response = stdnse.output_table()
  local request_time = os.time()
  local status, result = smb.get_os(host)
  local smb2_info

  if not status then
    -- SMB1 session setup failed; the host may have SMB1 disabled entirely
    -- (modern Windows, hardened Samba). Fall back to a pure SMB2 session.
    smb2_info = get_os_over_smb2(host)
    if not smb2_info then
      return stdnse.format_output(false, result)
    end
    result = {
      port = smb2_info.port,
      server = smb2_info.netbios_computer_name,
      domain = smb2_info.netbios_domain_name,
      time = smb2_info.time,
      os_major_version = smb2_info.os_major_version,
      os_minor_version = smb2_info.os_minor_version,
      os_build = smb2_info.os_build,
      fqdn = smb2_info.fqdn,
      domain_dns = smb2_info.dns_domain_name,
      forest_dns = smb2_info.dns_forest_name,
      smb_dialect = smb2_info.dialect,
    }
  else
    -- SMB1 worked. Modern Windows (10 1607+) blanks out the OS strings and
    -- never reports the build, so ask over SMB2 for the missing details.
    if not result.os_build or not result.fqdn then
      smb2_info = get_os_over_smb2(host)
      if smb2_info then
        result.os_major_version = result.os_major_version or smb2_info.os_major_version
        result.os_minor_version = result.os_minor_version or smb2_info.os_minor_version
        result.os_build = result.os_build or smb2_info.os_build
        result.fqdn = result.fqdn or smb2_info.fqdn
        result.domain_dns = result.domain_dns or smb2_info.dns_domain_name
        result.forest_dns = result.forest_dns or smb2_info.dns_forest_name
        result.smb_dialect = smb2_info.dialect
      end
    end
  end

  -- Collect results.
  response.os = result.os
  response.lanmanager = result.lanmanager
  response.domain = result.domain
  response.server = result.server
  if result.time and result.timezone then
    response.date = datetime.format_timestamp(result.time, result.timezone * 60 * 60)
    datetime.record_skew(host, result.time - result.timezone * 60 * 60, request_time)
  elseif result.time then
    -- SMB2 TargetInfo timestamps are UTC; the server timezone is unknown.
    response.date = datetime.format_timestamp(result.time)
  end
  response.fqdn = result.fqdn
  response.domain_dns = result.domain_dns
  response.forest_dns = result.forest_dns
  response.workgroup = result.workgroup
  response.smb_dialect = result.smb_dialect
  if result.os_build and result.os_build > 0 then
    response.os_version = string.format("%d.%d.%d",
      result.os_major_version or 0, result.os_minor_version or 0, result.os_build)
  end
  response.cpe = make_cpe(result)

  -- Build normal output.
  local output_lines = {}
  local friendly = friendly_windows_name(result.os_major_version, result.os_minor_version, result.os_build)
  if response.os and response.lanmanager then
    add_to_output(output_lines, "OS", string.format("%s (%s)", smb.get_windows_version(response.os), response.lanmanager))
  elseif friendly and result.os_build then
    add_to_output(output_lines, "OS", string.format("%s (build %d)", friendly, result.os_build))
  else
    add_to_output(output_lines, "OS", "Unknown")
  end
  add_to_output(output_lines, "OS CPE", response.cpe)
  if response.smb_dialect then
    add_to_output(output_lines, "SMB dialect", "SMB " .. response.smb_dialect)
  end
  if response.fqdn then
    -- Pull the first part of the FQDN as the computer name.
    add_to_output(output_lines, "Computer name", string.match(response.fqdn, "^([^.]+)%.?"))
  end
  add_to_output(output_lines, "NetBIOS computer name", result.server)
  if response.fqdn and response.domain_dns and response.fqdn ~= response.domain_dns then
    -- If the FQDN doesn't match the domain name, the target is a domain member.
    add_to_output(output_lines, "Domain name", response.domain_dns)
    add_to_output(output_lines, "Forest name", response.forest_dns)
    add_to_output(output_lines, "FQDN", response.fqdn)
    add_to_output(output_lines, "NetBIOS domain name", response.domain)
  else
    add_to_output(output_lines, "Workgroup", response.workgroup or response.domain)
  end
  add_to_output(output_lines, "System time", response.date or "Unknown")

  -- Augment service version detection
  if result.port and (response.lanmanager or friendly) then
    -- SMB session setup only ever runs over TCP; don't guess UDP for
    -- non-standard ports (this used to crash the script, since
    -- get_port_state() then returned nil and port.version was dereferenced
    -- unconditionally).
    local port = nmap.get_port_state(host, {number=result.port, protocol="tcp"})
    if port and port.version then
      if response.lanmanager and string.match(response.lanmanager, "^Samba ") then
        port.version.product = 'Samba smbd'
        port.version.version = string.match(response.lanmanager, "^Samba (.*)")
        nmap.set_port_version(host, port)
      elseif smb.get_windows_version(response.os) then
        port.version.product = string.format("%s %s", smb.get_windows_version(response.os), port.version.name)
        nmap.set_port_version(host, port)
      elseif friendly then
        port.version.product = string.format("%s %s", friendly, port.version.name)
        if result.os_build and result.os_build > 0 then
          port.version.version = string.format("%d.%d.%d",
            result.os_major_version or 0, result.os_minor_version or 0, result.os_build)
        end
        nmap.set_port_version(host, port)
      end
    end
  end

  return response, stdnse.format_output(true, output_lines)
end
