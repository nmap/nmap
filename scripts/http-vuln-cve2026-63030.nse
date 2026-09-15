local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects WordPress core installations vulnerable to "wp2shell", the
pre-authentication remote code execution chain formed by CVE-2026-63030 (a REST
API batch-endpoint route-confusion weakness in
WP_REST_Server::serve_batch_request_v1()) and CVE-2026-60137 (a SQL injection in
the author__not_in parameter of WP_Query).

Detection is performed purely by fingerprinting the WordPress core version from
publicly served resources (the "generator" meta tag on the home page and the
RSS feed generator). The script does NOT send any crafted request
to the batch endpoint and does NOT attempt exploitation, so it is safe to run
against production hosts.

Affected versions:
  * 6.9.0 - 6.9.4 and 7.0.0 - 7.0.1 are exposed to the full unauthenticated RCE
    chain (both CVEs) and are reported as VULNERABLE.
  * 6.8.0 - 6.8.5 are affected only by the SQL injection (CVE-2026-60137), not
    the full RCE chain, and are reported as LIKELY VULNERABLE.
  * 6.8.6, 6.9.5, 7.0.2 and later are patched.
  * Versions before 6.8.0 are not affected.

References:
  https://github.com/advisories/GHSA-ff9f-jf42-662q
  https://wordpress.org/documentation/wordpress-version/version-7-0-2/
]]

---
-- @usage
-- nmap -p 80,443 --script http-vuln-cve2026-63030 <target>
-- nmap --script http-vuln-cve2026-63030 --script-args http-vuln-cve2026-63030.root=/blog/ <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2026-63030:
-- |   VULNERABLE:
-- |   WordPress core pre-authentication RCE (wp2shell)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-63030
-- |     Risk factor: High
-- |       WordPress 7.0.1 is vulnerable to the wp2shell unauthenticated RCE
-- |       chain (CVE-2026-63030 + CVE-2026-60137).
-- |     Disclosure date: 2026-07-17
-- |     Extra information:
-- |       Detected WordPress 7.0.1 via generator meta tag (/).
-- |     References:
-- |       https://github.com/advisories/GHSA-ff9f-jf42-662q
-- |_      https://wordpress.org/documentation/wordpress-version/version-7-0-2/
--
-- @args http-vuln-cve2026-63030.root  Base path of the WordPress install
--       (default "/"). Use this when WordPress is served from a subdirectory.

author = "hwatsauce <muhammadabdullah8040@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

-- Turn a version string like "7.0.1" or "6.9" into a comparable integer so we
-- can do simple range checks (minor and patch numbers stay well under 100).
local function version_key(v)
  local major, minor, patch = v:match("^(%d+)%.(%d+)%.?(%d*)")
  if not major then
    return nil
  end
  return tonumber(major) * 10000 + tonumber(minor) * 100 + (tonumber(patch) or 0)
end

-- Normalize the user-supplied base path so it starts and ends with "/".
local function normalize_root(root)
  root = root or "/"
  if root:sub(1, 1) ~= "/" then root = "/" .. root end
  if root:sub(-1) ~= "/" then root = root .. "/" end
  return root
end

-- Attempt to recover the WordPress core version from public resources.
-- Returns version_string, source_description  (or nil if not found).
local function get_wp_version(host, port, root)
  -- 1) "generator" meta tag on the home page (handles either attribute order).
  local resp = http.get(host, port, root)
  if resp and resp.body then
    local v = resp.body:match('name="generator"%s+content="WordPress%s+([%d%.]+)"')
           or resp.body:match('content="WordPress%s+([%d%.]+)"%s+name="generator"')
    if v then
      return v, "generator meta tag (" .. root .. ")"
    end
  end

  -- 2) RSS feed generator, e.g. <generator>https://wordpress.org/?v=7.0.1</generator>
  resp = http.get(host, port, root .. "feed/")
  if resp and resp.body then
    local v = resp.body:match("wordpress%.org/%?v=([%d%.]+)")
    if v then
      return v, "RSS feed generator (" .. root .. "feed/)"
    end
  end

  return nil
end

action = function(host, port)
  local root = normalize_root(stdnse.get_script_args("http-vuln-cve2026-63030.root"))

  local vuln = {
    title = "WordPress core pre-authentication RCE (wp2shell)",
    state = vulns.STATE.NOT_VULN,
    -- The vulns IDS table takes one CVE key; the second CVE is noted in the
    -- description and extra_info below.
    IDS = { CVE = "CVE-2026-63030" },
    -- nmap's vulns library only accepts "High"/"Medium"/"Low"; "High" is the
    -- most severe tier available (there is no "Critical").
    risk_factor = "High",
    description = [[
wp2shell is an unauthenticated remote code execution chain in WordPress core.
CVE-2026-63030 is a route-confusion flaw in the REST API batch endpoint
(/wp-json/batch/v1) that lets an unvalidated sub-request reach a handler it was
never checked against; chained with the CVE-2026-60137 SQL injection in
WP_Query's author__not_in parameter, an anonymous attacker can forge an
administrator account and execute code. Exploitable on a default install with no
plugins, no configuration, and no authentication.]],
    references = {
      "https://github.com/advisories/GHSA-ff9f-jf42-662q",
      "https://wordpress.org/documentation/wordpress-version/version-7-0-2/",
    },
    dates = { disclosure = { year = 2026, month = 7, day = 17 } },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local version, source = get_wp_version(host, port, root)
  if not version then
    -- Could not confirm WordPress / determine a version: report nothing rather
    -- than emit a misleading result.
    stdnse.debug1("Could not determine WordPress version at %s", root)
    return nil
  end

  local key = version_key(version)
  if not key then
    return nil
  end

  if (key >= 60900 and key <= 60904) or (key >= 70000 and key <= 70001) then
    -- 6.9.0-6.9.4 and 7.0.0-7.0.1: full unauthenticated RCE chain.
    vuln.state = vulns.STATE.VULN
    vuln.extra_info = string.format(
      "Detected WordPress %s via %s. Vulnerable to the full wp2shell RCE chain "
      .. "(CVE-2026-63030 + CVE-2026-60137). Fixed in 6.9.5 / 7.0.2.",
      version, source)
  elseif key >= 60800 and key <= 60805 then
    -- 6.8.0-6.8.5: SQL injection only, not the full RCE chain.
    vuln.state = vulns.STATE.LIKELY_VULN
    vuln.risk_factor = "High"
    vuln.IDS = { CVE = "CVE-2026-60137" }
    vuln.extra_info = string.format(
      "Detected WordPress %s via %s. Affected by the CVE-2026-60137 SQL "
      .. "injection only (not the full wp2shell RCE chain). Fixed in 6.8.6.",
      version, source)
  else
    vuln.state = vulns.STATE.NOT_VULN
    vuln.extra_info = string.format(
      "Detected WordPress %s via %s. Not affected by wp2shell.", version, source)
  end

  return report:make_output(vuln)
end
