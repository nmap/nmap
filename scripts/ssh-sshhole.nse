local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detection-only check for the "*sshole" OpenSSH password-authentication bypass
(https://sshhole.com).

On musl-libc systems (Alpine, OpenWrt, Buildroot, Yocto, postmarketOS, void-musl,
Chimera) with sshd built WITHOUT PAM and with PasswordAuthentication enabled,
OpenSSH 7.3p1 through 10.6p1 lets you authenticate as any account whose password
field is exactly "*" (root on Alpine cloud images, key-only users, LDAP/AD users)
by sending any password longer than 256 bytes. Fixed in OpenSSH 10.6p2 (2026-11-05).

This script is SAFE: it does NOT attempt the bypass and never sends credentials.
It reads the SSH identification banner and grades the risk from the version and
the banner shape:

* a glibc/BSD build tag (Debian, Ubuntu, FreeBSD, ...) rules the bug out --
  it is musl-only, and these platforms stamp their banner;
* a bare banner with no "pN" portable suffix and no tag is the shape Alpine/musl
  produces (e.g. "OpenSSH_10.3") -> LIKELY, verify locally;
* a bare portable banner ("OpenSSH_10.3p1", no tag) is an upstream/source build
  on any libc -> POSSIBLE, verify locally.

The remaining preconditions -- musl libc for certain, sshd built without PAM,
PasswordAuthentication yes, an account with "*", and a donor sha-crypt hash on
the box -- CANNOT be confirmed remotely without actually performing the bypass,
so even the strongest result means "verify locally", not "confirmed exploitable".
(OpenBSD's native banner looks identical to Alpine's but is not affected.)

To confirm on a host you control, run the project's check.sh locally:
  https://raw.githubusercontent.com/oz9un/sshole/main/check.sh

Tracked as CVE-2026-123158. Note that Alpine backported the fix into every
branch WITHOUT changing the banner version (a patched 3.24 still reports
"OpenSSH_10.3"), so the banner cannot distinguish patched from unpatched Alpine
-- always confirm a positive locally.

References:
* https://sshhole.com
* https://nvd.nist.gov/vuln/detail/CVE-2026-123158
* https://cycode.com/blog/sshole-cve-2026-123158-openssh-alpine-linux-vulnerability/
* https://www.openssh.com/txt/release-10.6p2
]]

---
-- @usage
-- nmap -p 22 --script ssh-sshhole <target>
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 22/tcp open  ssh     OpenSSH 10.3 (protocol 2.0)
-- | ssh-sshhole:
-- |   VULNERABLE: LIKELY -- OpenSSH 10.3 is in the affected range 7.3p1..10.6p1 (no bypass attempted)
-- |   title: *sshole: OpenSSH password-auth bypass on musl without PAM
-- |   detected_version: OpenSSH 10.3
-- |   banner: SSH-2.0-OpenSSH_10.3
-- |   confidence: Banner has no portable 'pN' suffix and no build tag -- the shape
-- |     Alpine/musl produces. (OpenBSD looks the same but is not affected.) Verify locally.
-- |   risk_factor: High, but ONLY if musl libc + sshd without PAM + PasswordAuthentication yes
-- |   detail: Remote detection is banner-based... No bypass was attempted and no credentials were sent.
-- |   confirm_locally: curl -sO https://raw.githubusercontent.com/oz9un/sshole/main/check.sh && sudo sh check.sh
-- |   fix: Upgrade to OpenSSH 10.6p2 (e.g. apk upgrade openssh), or set PasswordAuthentication no.
-- |   disclosed: 2026-11-05
-- |   references:
-- |     https://sshhole.com
-- |_    https://www.openssh.com/txt/release-10.6p2
--
-- A Debian/Ubuntu/FreeBSD-tagged banner reports NOT_VULNERABLE (musl-only bug);
-- a bare portable banner ("OpenSSH_10.3p1") reports VULNERABLE: POSSIBLE.

author = "Zsigmond Murka-Moncz (zsigisti)"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"safe", "version", "vuln"}

portrule = shortport.port_or_service(22, "ssh")

-- Parse an OpenSSH version string like "10.3p1" into a comparable table.
-- Returns {major, minor, portable} or nil if it does not look like OpenSSH.
local function parse_openssh_version(ver)
  local major, minor, portable = ver:match("^(%d+)%.(%d+)p(%d+)")
  if major then
    return { tonumber(major), tonumber(minor), tonumber(portable) }
  end
  -- Some builds report "X.Y" with no portable suffix (treat as p0).
  major, minor = ver:match("^(%d+)%.(%d+)")
  if major then
    return { tonumber(major), tonumber(minor), 0 }
  end
  return nil
end

-- Compare two {major, minor, portable} tables. Returns -1, 0, or 1.
local function cmp_version(a, b)
  for i = 1, 3 do
    if a[i] < b[i] then return -1 end
    if a[i] > b[i] then return 1 end
  end
  return 0
end

-- Read the SSH identification banner from the target.
local function grab_banner(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then
    sock:close()
    return nil, ("could not connect: %s"):format(err)
  end
  -- The server sends its identification string first (RFC 4253 sec 4.2).
  local status, data = sock:receive_lines(1)
  sock:close()
  if not status then
    return nil, ("no banner received: %s"):format(data)
  end
  -- Keep only the first line, strip CR/LF.
  local banner = data:match("^[^\r\n]*") or data
  return banner
end

action = function(host, port)
  local banner, err = grab_banner(host, port)
  if not banner then
    return stdnse.format_output(false, err)
  end

  -- Expect "SSH-2.0-OpenSSH_<version>[ <build tag>]"
  -- The version token keeps any "pN" portable suffix; the build tag is whatever
  -- follows it (e.g. "Debian-2+deb12u3", "Ubuntu-3", "FreeBSD-20240806").
  local ver = banner:match("OpenSSH[_/]([%w%.]+)")
  if not ver then
    return ("Not OpenSSH, or version hidden. Banner: %s"):format(banner)
  end
  local tag = banner:match("OpenSSH[_/][%w%.]+%s+(.+)$")
  tag = tag and (tag:gsub("%s+$", "")) or ""
  local has_portable_suffix = ver:match("p%d+") ~= nil

  local parsed = parse_openssh_version(ver)
  if not parsed then
    return ("Could not parse OpenSSH version %q. Banner: %s"):format(ver, banner)
  end

  local FIRST_AFFECTED = { 7, 3, 1 }   -- 7.3p1, where pick_salt() introduced the bug
  local FIRST_FIXED    = { 10, 6, 2 }  -- 10.6p2, the upstream fix

  local in_range = cmp_version(parsed, FIRST_AFFECTED) >= 0
    and cmp_version(parsed, FIRST_FIXED) < 0

  local out = stdnse.output_table()

  -- A build tag naming a glibc/BSD platform rules the bug out entirely: the bug is
  -- musl-only. These platforms stamp their banner; Alpine/musl does not.
  local NONMUSL_TAGS = {
    "debian", "ubuntu", "raspbian", "freebsd", "netbsd", "openbsd",
    "sun_ssh", "centos", "red%s*hat", "rhel", "el[0-9]", "fips",
  }
  local tag_l = tag:lower()
  local nonmusl_hit = false
  if tag ~= "" then
    for _, pat in ipairs(NONMUSL_TAGS) do
      if tag_l:find(pat) then nonmusl_hit = true break end
    end
  end

  if nonmusl_hit then
    out.NOT_VULNERABLE = ("Banner build tag (%s) identifies a non-musl platform; the bug is musl-only."):format(tag)
    out.detected_version = "OpenSSH " .. ver
    out.banner = banner
    return out
  end

  if not in_range then
    out.NOT_VULNERABLE = ("OpenSSH %s is outside the affected range (7.3p1..10.6p1)"):format(ver)
    out.detected_version = "OpenSSH " .. ver
    out.banner = banner
    out.note = "Distros can backport the fix without bumping the version (and vice versa); "
      .. "verify locally if in doubt."
    return out
  end

  -- In range, and no non-musl tag. Grade confidence on the banner shape.
  -- Observed: Alpine/musl strips the "pN" portable suffix AND adds no build tag
  -- (e.g. "OpenSSH_10.3"). Upstream-portable and Arch/Gentoo/RHEL source builds
  -- keep the "pN" with no tag (e.g. "OpenSSH_10.3p1"). OpenBSD is also bare and
  -- p-less but is NOT affected, hence "likely" rather than "confirmed".
  local verdict, confidence
  if tag == "" and not has_portable_suffix then
    verdict = "LIKELY"
    confidence = "Banner has no portable 'pN' suffix and no build tag -- the shape "
      .. "Alpine/musl produces. (OpenBSD looks the same but is not affected.) "
      .. "Verify locally."
  elseif tag == "" and has_portable_suffix then
    verdict = "POSSIBLE"
    confidence = "Bare portable banner (has 'pN', no build tag): an upstream or "
      .. "source build on any libc -- could be musl (affected) or glibc (not). "
      .. "Verify locally."
  else
    verdict = "POSSIBLE"
    confidence = ("Unrecognized build tag (%s); cannot tell libc from the banner. "):format(tag)
      .. "Verify locally."
  end

  out.VULNERABLE = ("%s -- OpenSSH %s is in the affected range 7.3p1..10.6p1 "):format(verdict, ver)
    .. "(CVE-2026-123158; no bypass attempted)"
  out.title = "*sshole: OpenSSH password-auth bypass on musl without PAM"
  out.cve = "CVE-2026-123158"
  out.detected_version = "OpenSSH " .. ver
  out.banner = banner
  out.confidence = confidence
  out.risk_factor = "High, but ONLY if musl libc + sshd without PAM + PasswordAuthentication yes"
  out.detail = "Remote detection is banner-based: even the strongest banner shape "
    .. "cannot confirm musl libc for certain, nor the absence of PAM, the config, "
    .. "or the '*'/donor-hash account preconditions. Alpine also backports the fix "
    .. "without changing the banner version, so an in-range banner does not prove the "
    .. "host is unpatched. No bypass was attempted and no credentials were sent."
  out.confirm_locally = "curl -sO https://raw.githubusercontent.com/oz9un/sshole/main/check.sh && sudo sh check.sh"
  out.fix = "Upgrade to OpenSSH 10.6p2 / your distro's patched build (e.g. apk upgrade openssh), or set PasswordAuthentication no."
  out.disclosed = "2026-11-05"
  out.references = {
    "https://sshhole.com",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-123158",
    "https://www.openssh.com/txt/release-10.6p2",
  }
  return out
end
