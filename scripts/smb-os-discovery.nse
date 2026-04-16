local nmap = require "nmap"
local smb = require "smb"
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
-- |   OS: Windows 11 (build 22631) (Windows 10.0)
-- |   OS version: 10.0.22631
-- |   SMB dialect: SMB 3.1.1
-- |   OS CPE: cpe:/o:microsoft:windows_11::-
-- |   Computer name: desktop-abc
-- |   NetBIOS computer name: DESKTOP-ABC
-- |   Workgroup: WORKGROUP
-- |_  System time: 2026-04-16T13:34:06-05:00
--
--@xmloutput
-- <elem key="os">Windows 10.0 build 22631</elem>
-- <elem key="cpe">cpe:/o:microsoft:windows_11::-</elem>
-- <elem key="lanmanager">Windows 10.0</elem>
-- <elem key="nt_version">10.0.22631</elem>
-- <elem key="build">22631</elem>
-- <elem key="smb2_dialect">SMB 3.1.1</elem>
-- <elem key="domain">WORKGROUP</elem>
-- <elem key="server">DESKTOP-ABC</elem>
-- <elem key="date">2026-04-16T13:34:06-05:00</elem>

author = "golem445"
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
--
-- Windows 10 and later blank out the NativeOS/NativeLanMan strings, so modern
-- systems must be fingerprinted from the NTLMSSP Version field (result.os_major_version,
-- result.os_minor_version, result.os_build).
local function cpe_from_ntlm(major, minor, build, os_str)
  if major == nil or minor == nil then return nil end
  local is_server = os_str and string.find(os_str, "Server", 1, true)

  if major == 5 and minor == 0 then
    return {"o", "microsoft", "windows_2000"}
  elseif major == 5 and minor == 1 then
    return {"o", "microsoft", "windows_xp"}
  elseif major == 5 and minor == 2 then
    return is_server and {"o", "microsoft", "windows_server_2003"}
      or {"o", "microsoft", "windows_xp"}
  elseif major == 6 and minor == 0 then
    return is_server and {"o", "microsoft", "windows_server_2008"}
      or {"o", "microsoft", "windows_vista"}
  elseif major == 6 and minor == 1 then
    return is_server and {"o", "microsoft", "windows_server_2008", "r2"}
      or {"o", "microsoft", "windows_7"}
  elseif major == 6 and minor == 2 then
    return is_server and {"o", "microsoft", "windows_server_2012"}
      or {"o", "microsoft", "windows_8"}
  elseif major == 6 and minor == 3 then
    return is_server and {"o", "microsoft", "windows_server_2012", "r2"}
      or {"o", "microsoft", "windows_8.1"}
  elseif major == 10 and minor == 0 then
    if build == nil then return nil end
    -- Unambiguous Windows 11 ranges.
    if build >= 22000 and build < 26100 then
      return {"o", "microsoft", "windows_11"}
    end
    -- Unambiguous Windows Server ranges.
    if build == 20348 then
      return {"o", "microsoft", "windows_server_2022"}
    end
    if build == 25398 then
      return {"o", "microsoft", "windows_server_2022"} -- Server 23H2 (same family)
    end
    if build >= 26100 and build < 27000 then
      if is_server then return {"o", "microsoft", "windows_server_2025"} end
      return {"o", "microsoft", "windows_11"} -- build 26100 is Win11 24H2
    end
    if build >= 27000 then
      return {"o", "microsoft", "windows_11"}
    end
    -- Build numbers shared between client and server SKUs.
    if build == 14393 then
      return is_server and {"o", "microsoft", "windows_server_2016"}
        or {"o", "microsoft", "windows_10", "1607"}
    end
    if build == 17763 then
      return is_server and {"o", "microsoft", "windows_server_2019"}
        or {"o", "microsoft", "windows_10", "1809"}
    end
    -- Everything else in the 10.0.x range is a Windows 10 feature release.
    return {"o", "microsoft", "windows_10"}
  end
  return nil
end

function make_cpe(result)
  local os = result.os or ""
  local parts

  -- Prefer NTLM Version when present; it's authoritative.
  parts = cpe_from_ntlm(result.os_major_version, result.os_minor_version,
                        result.os_build, os)

  -- Fall back to the legacy OS string parsing.
  if parts == nil then
    parts = {}
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
    elseif string.match(os, "^Windows 11") then
      parts = {"o", "microsoft", "windows_11"}
    elseif string.match(os, "^Windows Server.*2025") then
      parts = {"o", "microsoft", "windows_server_2025"}
    elseif string.match(os, "^Windows Server.*2022") then
      parts = {"o", "microsoft", "windows_server_2022"}
    elseif string.match(os, "^Windows Server.*2019") then
      parts = {"o", "microsoft", "windows_server_2019"}
    elseif string.match(os, "^Windows Server.*2016") then
      parts = {"o", "microsoft", "windows_server_2016"}
    elseif string.match(os, "^Windows Server.*2012") then
      parts = {"o", "microsoft", "windows_server_2012"}
    end
  end

  if parts[1] == "o" and parts[2] == "microsoft"
    and string.match(parts[3], "^windows") then
    if parts[4] == nil then parts[4] = "" end
    local sp = string.match(os, "Service Pack (%d+)")
    if parts[5] == nil then
      if sp then
        parts[5] = "sp" .. tostring(sp)
      else
        parts[5] = "-"
      end
    end
    if string.match(os, "Professional") then
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

-- Human-readable SMB2 dialect. smb2.dialect_name would give us "3.1.1"
-- etc; we keep it local to avoid a hard dependency when the library is
-- unavailable.
local function smb2_dialect_str(d)
  if d == nil then return nil end
  if d == 0x0202 then return "SMB 2.0.2"
  elseif d == 0x0210 then return "SMB 2.1"
  elseif d == 0x0300 then return "SMB 3.0"
  elseif d == 0x0302 then return "SMB 3.0.2"
  elseif d == 0x0311 then return "SMB 3.1.1"
  end
  return string.format("SMB2 dialect 0x%04x", d)
end

action = function(host)
  local response = stdnse.output_table()
  local request_time = os.time()
  local status, result = smb.get_os(host)

  if(status == false) then
    return stdnse.format_output(false, result)
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
    response.date = datetime.format_timestamp(result.time)
  end
  response.fqdn = result.fqdn
  response.domain_dns = result.domain_dns
  response.forest_dns = result.forest_dns
  response.workgroup = result.workgroup
  response.cpe = make_cpe(result)

  -- Expose the NTLM Version triple so downstream consumers (xmloutput,
  -- other scripts) can see the authoritative build number.
  if result.os_major_version then
    response.nt_version = string.format("%d.%d.%d",
      result.os_major_version, result.os_minor_version, result.os_build or 0)
    response.build = result.os_build
  end
  response.smb2_dialect = smb2_dialect_str(result.smb2_dialect)

  -- Derive a friendly name: prefer NTLM-based detection when available.
  local friendly = smb.get_windows_version(result)

  -- Build normal output.
  local output_lines = {}
  if friendly and response.lanmanager and response.lanmanager ~= "" then
    add_to_output(output_lines, "OS", string.format("%s (%s)", friendly, response.lanmanager))
  elseif friendly then
    add_to_output(output_lines, "OS", friendly)
  elseif response.lanmanager and response.lanmanager ~= "" then
    add_to_output(output_lines, "OS", response.lanmanager)
  else
    add_to_output(output_lines, "OS", "Unknown")
  end
  if response.nt_version then
    add_to_output(output_lines, "OS version", response.nt_version)
  end
  if response.smb2_dialect then
    add_to_output(output_lines, "SMB dialect", response.smb2_dialect)
  end
  add_to_output(output_lines, "OS CPE", response.cpe)
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
    local proto
    if result.port == 445 or result.port == 139 then
      proto = 'tcp'
    else
      proto = 'udp'
    end

    local port = nmap.get_port_state(host,{number=result.port,protocol=proto})

    if response.lanmanager and string.match(response.lanmanager,"^Samba ") then
      port.version.product = 'Samba smbd'
      port.version.version = string.match(response.lanmanager,"^Samba (.*)")
      nmap.set_port_version(host,port)
    elseif friendly then
      port.version.product = string.format("%s %s", friendly, port.version.name)
      if result.os_build and result.os_build > 0 then
        port.version.version = string.format("%d.%d.%d",
          result.os_major_version, result.os_minor_version, result.os_build)
      end
      nmap.set_port_version(host,port)
    end
  end

  return response, stdnse.format_output(true, output_lines)
end
