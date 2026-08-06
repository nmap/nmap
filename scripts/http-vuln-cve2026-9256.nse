local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects NGINX servers vulnerable to CVE-2026-9256, a heap-based buffer
overflow in the ngx_http_rewrite_module. Affects NGINX Open Source 1.0.0
through 1.30.1 and version 1.31.0, and various NGINX Plus releases. An
unauthenticated attacker can trigger a heap buffer overflow via crafted
HTTP requests using overlapping PCRE captures.
]]

---
-- @usage
-- nmap -p 80,443 --script http-vuln-cve2026-9256 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2026-9256:
-- |   VULNERABLE:
-- |   NGINX ngx_http_rewrite_module Heap Buffer Overflow
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2026-9256
-- |     Risk factor: High  CVSSv4: 9.2
-- |     Description:
-- |       NGINX Open Source 1.0.0 through 1.30.1...
-- |     Disclosure date: 2026-05-22
-- |     Extra information:
-- |       Detected nginx version: 1.30.0
-- |     References:
-- |       https://my.f5.com/manage/s/article/K000161377
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2026-9256
---

author = "Ishaan Jindal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function parse_version(ver_str)
  local parts = {}
  for part in string.gmatch(ver_str, "%d+") do
    parts[#parts + 1] = tonumber(part)
  end
  return parts
end

local function version_lt(a, b)
  for i = 1, math.max(#a, #b) do
    local pa, pb = a[i] or 0, b[i] or 0
    if pa < pb then return true end
    if pa > pb then return false end
  end
  return false
end

local function version_gte(a, b)
  return not version_lt(a, b)
end

local function get_nginx_version(host, port)
  local result = http.get(host, port, "/")
  if result and result.status then
    local server = result.header["server"]
    if server then
      local ver = string.match(server, "nginx/([%d.]+)")
      if ver then
        return ver, string.format("HTTP Server header (nginx/%s)", ver)
      end
      local plus_ver = string.match(server, "[Nn]ginx%-?[Pp]lus[^-]*-[Rr](%d+)")
      if plus_ver then
        return plus_ver, string.format("HTTP Server header (NGINX Plus R%s)", plus_ver)
      end
    end
  end

  local fb = http.get(host, port, "/nmap-cve-check")
  if fb and fb.status then
    local ver = string.match(fb.body or "", "nginx/([%d.]+)")
    if ver then
      return ver, string.format("Error page body (nginx/%s)", ver)
    end
  end

  return nil, nil
end

action = function(host, port)
  local vuln = {
    title = "NGINX ngx_http_rewrite_module Heap Buffer Overflow",
    state = vulns.STATE.NOT_VULN,
    description = [[
NGINX Open Source 1.0.0 through 1.30.1 and version 1.31.0 are vulnerable to
a heap-based buffer overflow in the ngx_http_rewrite_module. When a rewrite
directive uses a regex pattern with overlapping PCRE captures and a
replacement string referencing multiple captures, a heap buffer overflow can
occur, potentially allowing denial of service or remote code execution.
    ]],
    IDS = {
      CVE = "CVE-2026-9256"
    },
    risk_factor = "High",
    scores = {
      CVSSv4 = "9.2"
    },
    references = {
      "https://my.f5.com/manage/s/article/K000161377",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-9256"
    },
    dates = {
      disclosure = { year = "2026", month = "05", day = "22" }
    },
    extra_info = {},
    check_results = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local ver_str, ver_source = get_nginx_version(host, port)
  if not ver_str then
    return vuln_report:make_output(vuln)
  end

  table.insert(vuln.extra_info, ver_source)

  local ver = parse_version(ver_str)
  if #ver < 2 then
    return vuln_report:make_output(vuln)
  end

  -- Affected: 1.0.0 <= ver < 1.30.2, or ver == 1.31.0
  if version_gte(ver, parse_version("1.0.0")) and
     version_lt(ver, parse_version("1.30.2")) then
    vuln.state = vulns.STATE.LIKELY_VULN
    table.insert(vuln.check_results, "Affected version range: Open Source 1.0.0 through 1.30.1")
  elseif ver[1] == 1 and ver[2] == 31 and (ver[3] or 0) == 0 and (ver[4] or 0) == 0 then
    vuln.state = vulns.STATE.LIKELY_VULN
    table.insert(vuln.check_results, "Affected version: Open Source 1.31.0")
  end

  return vuln_report:make_output(vuln)
end
