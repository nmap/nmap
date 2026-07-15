local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local vulns = require "vulns"

description = [[
Detects CVE-2026-14345, an unauthenticated remote code execution vulnerability in
WPFunnels, a WordPress funnel builder plugin by getwpfunnels.com. Versions up to
and including 3.12.7 allow unauthenticated attackers to inject arbitrary PHP code
into a server-side log file via the postData parameter. When an administrator
subsequently views the log through the plugin's Log Settings UI, the injected
code is executed via PHP's include_once.

The vulnerability exists because the plugin fails to sanitize attacker-controlled
values written to a .log file (CWE-434). The nonce required to reach the
vulnerable optin endpoint is publicly emitted on every funnel step page, making
the injection step fully unauthenticated.

Detection works in two layers:
1. Version manifest check — retrieves the plugin version from
   /wp-content/plugins/wpfunnels/readme.txt (or the plugin header as fallback)
   and compares against the fixed version (3.12.8).
2. Endpoint probe — POSTs to /wp-admin/admin-ajax.php with action=wpfnl_log and
   postData when the version is within the vulnerable range or unobtainable.
   WordPress AJAX returns "0" for unregistered actions, "-1" when the handler
   enforces a nonce check that fails, and the handler's output otherwise.
   A non-"0" response confirms the vulnerable action handler is registered;
   if the version is unknown, it is reported as LIKELY_VULN to avoid false
   positives on patched installations.

The base path is auto-detected by trying common WordPress installation directories.
Override with: --script-args http-vuln-cve2026-14345.path=/custom/path
]]

---
-- @usage
-- nmap -p80,443 --script http-vuln-cve2026-14345 <target>
-- nmap -p80,443 --script http-vuln-cve2026-14345 --script-args http-vuln-cve2026-14345.path=/wordpress <target>
--
-- @output
-- | http-vuln-cve2026-14345:
-- |   VULNERABLE:
-- |   WPFunnels WordPress Unauthenticated RCE
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-14345
-- |       WPFunnels plugin for WordPress versions up to 3.12.7 allow
-- |       unauthenticated attackers to inject PHP code via the postData
-- |       parameter into a log file that is subsequently executed via
-- |       include_once when an admin views the log (CVSS 9.8).
-- |
-- |     Disclosure date: 2026-07-06
-- |     References:
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-14345
-- |       https://wordpress.org/plugins/wpfunnels/
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-14345
--
-- @xmloutput
-- <elem key="title">WPFunnels WordPress Unauthenticated RCE</elem>
-- <elem key="state">VULNERABLE</elem>
-- <elem key="cve">CVE-2026-14345</elem>
--
-- @args http-vuln-cve2026-14345.path Base path to WordPress installation (auto-detected if not provided)
--

author = "Aditya Agrawal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.http

local EP_ACTION_ACTIVE = 1
local EP_ACTION_BLOCKED = 2
local EP_ACTION_ABSENT = 3

local COMMON_WP_PATHS = {"", "/wordpress", "/wp", "/blog", "/site", "/cms"}

local function version_ge(v1, v2)
  local function split(v)
    local parts = {}
    for part in v:gmatch("%d+") do
      parts[#parts + 1] = tonumber(part)
    end
    return parts
  end
  local p1, p2 = split(v1), split(v2)
  for i = 1, math.max(#p1, #p2) do
    local a, b = p1[i] or 0, p2[i] or 0
    if a ~= b then
      return a > b
    end
  end
  return true
end

local function version_lt(v1, v2)
  local function split(v)
    local parts = {}
    for part in v:gmatch("%d+") do
      parts[#parts + 1] = tonumber(part)
    end
    return parts
  end
  local p1, p2 = split(v1), split(v2)
  for i = 1, math.max(#p1, #p2) do
    local a, b = p1[i] or 0, p2[i] or 0
    if a ~= b then
      return a < b
    end
  end
  return false
end

local function strip_bom_and_whitespace(body)
  if not body or #body == 0 then
    return body
  end
  if #body >= 3 then
    local b1, b2, b3 = string.byte(body, 1), string.byte(body, 2), string.byte(body, 3)
    if b1 == 0xEF and b2 == 0xBB and b3 == 0xBF then
      body = string.sub(body, 4)
    end
  end
  body = string.match(body, "^%s*(.-)%s*$")
  return body or ""
end

local function classify_ajax_response(resp)
  if not resp then
    return nil
  end
  if resp.status ~= 200 then
    return nil
  end
  if not resp.body or #resp.body == 0 then
    return nil
  end
  local body = strip_bom_and_whitespace(resp.body)
  if #body == 0 then
    return nil
  end
  if string.match(body, "^%s*0%s*$") then
    return EP_ACTION_ABSENT
  end
  local ok, data = json.parse(body)
  if ok and type(data) == "table" then
    return EP_ACTION_ACTIVE
  end
  if string.match(body, "^%s*-1%s*$") then
    return EP_ACTION_BLOCKED
  end
  local trimmed = string.match(body, "^%s*(.*)")
  if trimmed and string.sub(trimmed, 1, 1) == "<" then
    return nil
  end
  return EP_ACTION_ACTIVE
end

local function try_get_version(host, port, base_path)
  local readme_path = base_path .. "/wp-content/plugins/wpfunnels/readme.txt"
  local resp = http.get(host, port, readme_path)
  if resp and resp.status == 200 and resp.body then
    local ver = string.match(resp.body, "Stable tag:%s*([%d.]+)")
    if ver then
      ver = string.match(ver, "%d[%d%.]*")
      if ver then
        return ver
      end
    end
  end
  local plugin_path = base_path .. "/wp-content/plugins/wpfunnels/wpfunnels.php"
  resp = http.get(host, port, plugin_path)
  if resp and resp.status == 200 and resp.body then
    if string.find(resp.body, "Plugin Name:%s*WPFunnels") then
      local ver = string.match(resp.body, "[Vv]ersion:%s*([%d.]+)")
      if ver then
        ver = string.match(ver, "%d[%d%.]*")
        if ver then
          return ver
        end
      end
    end
  end
  return nil
end

local function find_base_path(host, port)
  local path_arg = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  if path_arg and #path_arg > 0 then
    return path_arg
  end
  for _, p in ipairs(COMMON_WP_PATHS) do
    local readme = p .. "/wp-content/plugins/wpfunnels/readme.txt"
    local resp = http.get(host, port, readme)
    if resp and resp.status == 200 then
      return p
    end
  end
  return ""
end

action = function(host, port)
  local vuln = {
    title = "WPFunnels WordPress Unauthenticated RCE",
    state = vulns.STATE.NOT_VULN,
    description = [[
WPFunnels plugin for WordPress versions up to 3.12.7 allow unauthenticated
attackers to inject PHP code via the postData parameter into a log file that
is subsequently executed via include_once when an admin views the log (CVSS 9.8).
]],
    IDS = {CVE = "CVE-2026-14345"},
    references = {
      "https://nvd.nist.gov/vuln/detail/CVE-2026-14345",
      "https://wordpress.org/plugins/wpfunnels/",
    },
    dates = {disclosure = {year = "2026", month = "07", day = "06"}},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local base_path = find_base_path(host, port)
  local found_version = try_get_version(host, port, base_path)
  if found_version then
    if version_ge(found_version, "3.12.8") then
      return report:make_output(vuln)
    end
    if version_lt(found_version, "1.0.0") then
      return report:make_output(vuln)
    end
  end
  local ajax_path = base_path .. "/wp-admin/admin-ajax.php"
  local resp = http.post(host, port, ajax_path, {
    header = {["Content-Type"] = "application/x-www-form-urlencoded"},
    content = "action=wpfnl_log&postData=CVE-2026-14345-probe",
  })
  local ep_class = classify_ajax_response(resp)
  if ep_class == EP_ACTION_ACTIVE or ep_class == EP_ACTION_BLOCKED then
    if found_version then
      vuln.state = vulns.STATE.VULN
    else
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  elseif ep_class == EP_ACTION_ABSENT then
    if found_version then
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  end
  return report:make_output(vuln)
end
