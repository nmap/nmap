local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local rand = require "rand"
local vulns = require "vulns"

description = [[
Detects CVE-2026-48908, an unauthenticated remote code execution vulnerability in
SP Page Builder for Joomla by JoomShaper. Versions 1.0.0 through 6.6.1 allow
unauthenticated attackers to upload arbitrary files via the asset.uploadCustomIcon
task, leading to PHP code execution and full server compromise.

The vulnerability resides in com_sppagebuilder's asset controller which performs
no authentication or file-type validation on the icon upload endpoint.

Detection first checks the extension version manifest; only if the version is
within the vulnerable range (or unobtainable) does it probe the upload controller
with a multipart request carrying an empty ZIP archive. The response is classified
by authentication behavior and JSON semantics:
  - Controller reached + no auth enforced + version vulnerable   → VULN
  - Controller reached + no auth enforced + version unknown      → LIKELY_VULN
  - Controller reached + auth enforced (401, 403, login redirect) → LIKELY_VULN

The base path is auto-detected by trying common Joomla installation directories.
Override with: --script-args http-vuln-cve2026-48908.path=/custom/path
]]

---
-- @usage
-- nmap -p80,443 --script http-vuln-cve2026-48908 <target>
-- nmap -p80,443 --script http-vuln-cve2026-48908 --script-args http-vuln-cve2026-48908.path=/joomla <target>
--
-- @output
-- | http-vuln-cve2026-48908:
-- |   VULNERABLE:
-- |   SP Page Builder for Joomla Unauthenticated RCE
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-48908
-- |       SP Page Builder for Joomla versions 1.0.0 through 6.6.1 allow
-- |       unauthenticated attackers to upload arbitrary files via the
-- |       asset.uploadCustomIcon task, leading to PHP code execution
-- |       and full server compromise (CVSS 10.0).
-- |
-- |     Disclosure date: 2026-06-20
-- |     References:
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-48908
-- |       https://www.joomshaper.com/page-builder
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48908
--
-- @xmloutput
-- <elem key="title">SP Page Builder for Joomla Unauthenticated RCE</elem>
-- <elem key="state">VULNERABLE</elem>
-- <elem key="cve">CVE-2026-48908</elem>
--
-- @args http-vuln-cve2026-48908.path Base path to Joomla installation (auto-detected if not provided)
--

author = "Aditya Agrawal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.http

local EP_UNPROTECTED = 1
local EP_AUTH_ENFORCED = 2
local EP_PRESENT_METHOD_REJECTED = 3
local EP_ABSENT = 4

local AUTH_KEYWORDS = {
  "login", "log in",
  "authoris", "authoriz",
  "permission", "permit",
  "denied", "deny",
  "token", "csrf",
  "not allowed", "not authorised", "not authorized",
  "unauthenticated", "unauthorized", "unauthorised",
}

local LOGIN_PATH_INDICATORS = {
  "login", "com_users", "return", "administrator",
  "auth", "signin", "sign-in", "logon", "log-on",
}

local COMMON_JOOMLA_PATHS = {"", "/joomla", "/cms", "/site", "/joomla3", "/joomla4"}

local MANIFEST_PATHS = {
  "administrator/components/com_sppagebuilder/sp_page_builder.xml",
  "administrator/components/com_sppagebuilder/sppagebuilder.xml",
  "administrator/components/com_sppagebuilder/com_sppagebuilder.xml",
}

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

local function body_is_html(body)
  if not body or #body == 0 then
    return false
  end
  local sample = string.sub(body, 1, math.min(#body, 500))
  if #sample >= 3 then
    local b1, b2, b3 = string.byte(sample, 1), string.byte(sample, 2), string.byte(sample, 3)
    if b1 == 0xEF and b2 == 0xBB and b3 == 0xBF then
      sample = string.sub(sample, 4)
    end
  end
  sample = string.match(sample, "^%s*(.*)") or sample
  local lower = string.lower(sample)
  for _, tag in ipairs({"<!doctype", "<html", "<head", "<body"}) do
    if string.find(lower, tag, 1, true) then
      return true
    end
  end
  return false
end

local function has_json_content_type(resp)
  if resp and resp.header then
    local ct = resp.header["content-type"] or ""
    return string.find(string.lower(ct), "json") ~= nil
  end
  return false
end

local function response_looks_like_json(body)
  if not body then
    return false
  end
  local trimmed = string.match(body, "^%s*(.*)")
  if not trimmed or trimmed == "" then
    return false
  end
  return string.sub(trimmed, 1, 1) == "{"
end

local function is_joomla_json_format(data)
  if type(data) ~= "table" then
    return false
  end
  if data.success ~= nil then
    return true
  end
  if data.status ~= nil then
    return true
  end
  if data.message ~= nil or data.msg ~= nil then
    return true
  end
  if data.data ~= nil then
    return true
  end
  return false
end

local function indicates_auth(json_data)
  if type(json_data) ~= "table" then
    return false
  end
  for _, key in ipairs({"auth", "authenticated", "authorized", "authorised",
                         "login", "token", "csrf"}) do
    if type(json_data[key]) == "string" then
      return true
    end
  end
  local function collect_strings(tbl, out)
    for _, v in pairs(tbl) do
      if type(v) == "string" then
        table.insert(out, string.lower(v))
      elseif type(v) == "table" then
        collect_strings(v, out)
      end
    end
  end
  local all_strings = {}
  collect_strings(json_data, all_strings)
  for _, msg in ipairs(all_strings) do
    for _, kw in ipairs(AUTH_KEYWORDS) do
      if string.find(msg, kw, 1, true) then
        return true
      end
    end
  end
  return false
end

local function is_controller_response(resp)
  if not resp or not resp.body or #resp.body == 0 then
    return false
  end
  if body_is_html(resp.body) then
    return false
  end
  if not has_json_content_type(resp) and not response_looks_like_json(resp.body) then
    return false
  end
  local ok, data = json.parse(resp.body)
  if not ok or type(data) ~= "table" then
    return false
  end
  if not is_joomla_json_format(data) then
    return false
  end
  return not indicates_auth(data)
end

local function is_auth_response(resp)
  if not resp or not resp.body or #resp.body == 0 then
    return false
  end
  if body_is_html(resp.body) then
    return false
  end
  if not has_json_content_type(resp) and not response_looks_like_json(resp.body) then
    return false
  end
  local ok, data = json.parse(resp.body)
  if not ok or type(data) ~= "table" then
    return false
  end
  if not is_joomla_json_format(data) then
    return false
  end
  return indicates_auth(data)
end

local function is_login_redirect(resp)
  if not resp or not resp.header then
    return false
  end
  local loc = string.lower(resp.header["location"] or "")
  for _, indicator in ipairs(LOGIN_PATH_INDICATORS) do
    if string.find(loc, indicator, 1, true) then
      return true
    end
  end
  if resp.rawheader then
    for _, line in ipairs(resp.rawheader) do
      local lower = string.lower(line)
      if string.find(lower, "^set%-cookie:", 1) then
        if string.find(lower, "session", 1, true) or
           string.find(lower, "joomla", 1, true) then
          return true
        end
      end
    end
  end
  return false
end

local function classify_endpoint(resp)
  if not resp then
    return nil
  end
  if resp.status == 200 then
    if is_controller_response(resp) then
      return EP_UNPROTECTED
    end
    if is_auth_response(resp) then
      return EP_AUTH_ENFORCED
    end
  end
  if resp.status == 401 or resp.status == 403 then
    return EP_AUTH_ENFORCED
  end
  if resp.status >= 300 and resp.status < 400 then
    if is_login_redirect(resp) then
      return EP_AUTH_ENFORCED
    end
    return EP_ABSENT
  end
  if resp.status == 404 then
    return EP_ABSENT
  end
  if resp.status == 405 then
    return EP_PRESENT_METHOD_REJECTED
  end
  if resp.status >= 500 then
    return nil
  end
  return nil
end

local function try_get_version(host, port, base_path)
  for _, manifest_rel in ipairs(MANIFEST_PATHS) do
    local manifest_path = base_path .. "/" .. manifest_rel
    local resp = http.get(host, port, manifest_path)
    if resp and resp.status == 200 and resp.body then
      local ver = string.match(resp.body, "<version>([^<]+)</version>")
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
    path_arg = string.match(path_arg, "^(.-)/*$") or path_arg
    return path_arg
  end
  for _, p in ipairs(COMMON_JOOMLA_PATHS) do
    local manifest = p .. "/administrator/components/com_sppagebuilder/sp_page_builder.xml"
    local resp = http.get(host, port, manifest)
    if resp and resp.status == 200 then
      return p
    end
  end
  return ""
end

local function build_probe_parts()
  local boundary = "----NseB" .. rand.random_alpha(8)
  local empty_zip = string.char(
    0x50, 0x4B, 0x05, 0x06,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  )
  local parts = {}
  table.insert(parts, "--" .. boundary)
  table.insert(parts, 'Content-Disposition: form-data; name="custom_icon"; filename="icon.zip"')
  table.insert(parts, "Content-Type: application/zip")
  table.insert(parts, "")
  table.insert(parts, empty_zip)
  table.insert(parts, "--" .. boundary .. "--")
  return boundary, table.concat(parts, "\r\n")
end

local function probe_endpoint(host, port, base_path, probe_suffixes)
  local boundary, body = build_probe_parts()
  local best = nil
  for _, suffix in ipairs(probe_suffixes) do
    local url = base_path .. suffix
    local resp = http.post(host, port, url, {
      header = {["Content-Type"] = "multipart/form-data; boundary=" .. boundary},
      content = body,
    })
    local ep = classify_endpoint(resp)
    if ep == EP_UNPROTECTED then
      return EP_UNPROTECTED
    end
    if ep ~= nil and ep ~= EP_ABSENT then
      return ep
    end
    if ep == EP_ABSENT and best == nil then
      best = EP_ABSENT
    end
  end
  return best
end

local function combine_classifications(c1, c2)
  if c1 == EP_UNPROTECTED or c2 == EP_UNPROTECTED then
    return EP_UNPROTECTED
  end
  if c1 == nil then return c2 end
  if c2 == nil then return c1 end
  if c1 == EP_ABSENT then return c2 end
  if c2 == EP_ABSENT then return c1 end
  return math.min(c1, c2)
end

action = function(host, port)
  local vuln = {
    title = "SP Page Builder for Joomla Unauthenticated RCE",
    state = vulns.STATE.NOT_VULN,
    description = [[
SP Page Builder for Joomla versions 1.0.0 through 6.6.1 allow unauthenticated
attackers to upload arbitrary files via the asset.uploadCustomIcon task,
leading to PHP code execution and full server compromise (CVSS 10.0).
]],
    IDS = {CVE = "CVE-2026-48908"},
    references = {
      "https://nvd.nist.gov/vuln/detail/CVE-2026-48908",
      "https://www.joomshaper.com/page-builder",
    },
    dates = {disclosure = {year = "2026", month = "06", day = "20"}},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local base_path = find_base_path(host, port)
  local found_version = try_get_version(host, port, base_path)
  if found_version and version_lt(found_version, "1.0.0") then
    return report:make_output(vuln)
  end
  local ep_class = probe_endpoint(host, port, base_path, {
    "/index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon",
  })
  if ep_class ~= EP_UNPROTECTED then
    local ep_class2 = probe_endpoint(host, port, base_path, {
      "/index.php?option=com_sppagebuilder&task=editor.uploadIcons",
      "/administrator/index.php?option=com_sppagebuilder&task=editor.uploadIcons",
    })
    ep_class = combine_classifications(ep_class, ep_class2)
  end
  if ep_class == EP_UNPROTECTED then
    if found_version then
      vuln.state = vulns.STATE.VULN
    else
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  elseif ep_class == EP_AUTH_ENFORCED then
    if found_version and version_ge(found_version, "6.6.2") then
      vuln.state = vulns.STATE.NOT_VULN
    else
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  elseif ep_class == EP_PRESENT_METHOD_REJECTED then
    vuln.state = vulns.STATE.LIKELY_VULN
  elseif ep_class == EP_ABSENT then
    if found_version and not version_ge(found_version, "6.6.2") then
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  end
  return report:make_output(vuln)
end
