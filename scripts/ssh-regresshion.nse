local nmap = require "nmap"
local comm = require "comm"
local stdnse = require "stdnse"

description = [[
CVE-2024-6387 - Check for SSH regreSSHion vulnerability
]]

---
-- @usage
-- nmap -p <port> --script ssh-regresshion <target>
--
-- @output
-- PORT    STATE SERVICE
-- /tcp  open  http
-- |   VULNERABLE:
-- |   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.11 is vulnerable to RegreSSHion.
--
-- @args

author = "Jonathan Kennard"
license = "Autobahn Security"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

-- List of known vulnerable OpenSSH versions
local vulnerable_versions = {
  'SSH-2.0-OpenSSH_1', 'SSH-2.0-OpenSSH_2', 'SSH-2.0-OpenSSH_3',
  'SSH-2.0-OpenSSH_4.0', 'SSH-2.0-OpenSSH_4.1', 'SSH-2.0-OpenSSH_4.2',
  'SSH-2.0-OpenSSH_4.3', 'SSH-2.0-OpenSSH_4.4',
  'SSH-2.0-OpenSSH_8.5', 'SSH-2.0-OpenSSH_8.6', 'SSH-2.0-OpenSSH_8.7',
  'SSH-2.0-OpenSSH_8.8', 'SSH-2.0-OpenSSH_8.9',
  'SSH-2.0-OpenSSH_9.0', 'SSH-2.0-OpenSSH_9.1', 'SSH-2.0-OpenSSH_9.2',
  'SSH-2.0-OpenSSH_9.3', 'SSH-2.0-OpenSSH_9.4', 'SSH-2.0-OpenSSH_9.5',
  'SSH-2.0-OpenSSH_9.6', 'SSH-2.0-OpenSSH_9.7'
}

-- Split string function
local function split(inputstr, sep)
  sep = sep or "%s"  -- default separator is space
  local t = {}
  for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
    table.insert(t, str)
  end
  return t
end

local function split_literal(str, sep)
  local result = {}
  local pattern = "(.-)" .. sep:gsub("([^%w])", "%%%1")  -- escape special chars
  local last_end = 1
  local s, e, cap = str:find(pattern, 1)
  while s do
    table.insert(result, cap)
    last_end = e + 1
    s, e, cap = str:find(pattern, last_end)
  end
  table.insert(result, str:sub(last_end))
  return result
end

-- Helper to check if banner contains any vulnerable version string
local function is_vulnerable_banner(banner)
  for _, vuln in ipairs(vulnerable_versions) do
    -- stdnse.print_debug(1, banner)
    if banner:find(vuln, 1, true) then
      return true
    end
  end
  return false
end

-- Helper to check if banner suffix is safe
local function is_not_patched(banner)
  split_result = split_literal(banner, " ")

  banner_suffix = split_result[#split_result]  

  if string.find(banner_suffix:lower(), "ubuntu") then
    split_ubuntu = split_literal(banner_suffix:lower(), "ubuntu-")

    ubuntu_suffix = split_ubuntu[#split_ubuntu]
    -- Check Ubuntu suffix version
    stdnse.print_debug(1, "ubuntu--split value: %s", ubuntu_suffix)
    -- Trim whitespace
    ubuntu_suffix = ubuntu_suffix:match("^%s*(.-)%s*$")

    -- Process suffix to check patched version
    ubuntu_suffix_splitted = split_literal(ubuntu_suffix, "ubuntu")
    ubuntu_package_revision = tonumber(ubuntu_suffix_splitted[1]) or 0
    ubuntu_version_update = split_literal(ubuntu_suffix_splitted[2] or "0.0", ".")
    ubuntu_patch_series = tonumber(ubuntu_version_update[1]) or 0
    ubuntu_update_number = tonumber(ubuntu_version_update[2]) or 0

    stdnse.print_debug(1, "ubuntu_package_revision %s", ubuntu_package_revision)
    stdnse.print_debug(1, "ubuntu_patch_series %s", ubuntu_patch_series)
    stdnse.print_debug(1, "ubuntu_update_number %s", ubuntu_update_number)

    if ubuntu_package_revision == 1 and string.find(banner:lower(), "openssh_9.3") then
      if ubuntu_patch_series == 3 then
        if ubuntu_update_number >= 6 then
          return false
        else
          return true
        end
      else
        return true
      end
    elseif ubuntu_package_revision == 3 then
      if ubuntu_patch_series == 0 and string.find(banner:lower(), "openssh_8.9") then
        if ubuntu_update_number >= 10 then
          return false
        else
          return true
        end
      elseif ubuntu_patch_series == 3 and string.find(banner:lower(), "openssh_9.3") then
        
        if ubuntu_update_number >= 6 then
          return false
        else
          return true
        end
      elseif ubuntu_patch_series == 13 and string.find(banner:lower(), "openssh_9.6") then
        if ubuntu_update_number >= 3 then
          return false
        else
          return true
        end
      else
        return true
      end
    else
      return true
    end

  elseif string.find(banner_suffix:lower(), "debian") then
    split_debian = split_literal(banner_suffix:lower(), "debian-")

    debian_suffix = split_debian[#split_debian]
    -- Check Debian suffix version
    stdnse.print_debug(1, "debian--split value: %s", debian_suffix)
    -- Trim whitespace
    debian_suffix = debian_suffix:match("^%s*(.-)%s*$")

    -- Process suffix to check patched version
    debian_suffix_splitted = split_literal(debian_suffix, "+deb")
    debian_package_revision = tonumber(debian_suffix_splitted[1]) or 0
    debian_version_update = split_literal(debian_suffix_splitted[2] or "0u0", "u")
    debian_version = tonumber(debian_version_update[1]) or 0
    debian_update = tonumber(debian_version_update[2]) or 0

    stdnse.print_debug(1, "debian_package_revision %s", debian_package_revision)
    stdnse.print_debug(1, "debian_version %s", debian_version)
    stdnse.print_debug(1, "debian_update %s", debian_update)

    if debian_package_revision == 2 then
      if debian_version == 12 then
        if debian_update >= 3 then
          return false
        else
          return true
        end
      elseif debian_version > 12 then
        return false
      else
        return true
      end
    elseif debian_package_revision == 5 then
      if debian_version == 11 then
        if debian_update >= 3 then
          return false
        else
          return true
        end
      elseif debian_version > 11 then
        return false
      else
        return true
      end
    elseif debian_package_revision >= 7 then
      return false
    else
      return true
    end

  elseif string.find(banner_suffix:lower(), "freebsd") then
    split_freebsd = split_literal(banner_suffix:lower(), "freebsd-")
    freebsd_suffix = split_freebsd[#split_freebsd]
    -- Check FreeBSD suffix version
    stdnse.print_debug(1, "freebsd--split value: %s", freebsd_suffix)
    -- Trim whitespace
    freebsd_suffix = freebsd_suffix:match("^%s*(.-)%s*$")
    -- Process suffix to check patched version
    if (freebsd_suffix >= "20240701") and (string.find(banner:lower(), "openssh_9.6") or string.find(banner:lower(), "openssh_9.7")) then
      return false
    else
      return true
    end
  else
    return true
  end
  return false
end

action = function(host, port)
  local opts = { timeout = 3000 }
  local status, banner = comm.get_banner(host, port, opts)

  if not status then
    return "No banner received: " .. (banner or "unknown error")
  end

  banner = banner:match("^%s*(.-)%s*$") or ""

  vuln_banner = is_vulnerable_banner(banner)

  unpatched = is_not_patched(banner)

  if vuln_banner and unpatched then
    return string.format([[

    %s is vulnerable to RegreSSHion.
    Recommendation: Upgrade to patched version.
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387
    ]], banner)
  else
    return banner .. " is not vulnerable to RegreSSHion."
  end

end
