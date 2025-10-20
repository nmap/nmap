-- prometheus-metrics-audit.nse
-- Author: Shaheer Yasir (@shaheeryasirofficial)
-- Description: Detect and audit Prometheus /metrics endpoints. Parse metric names, types, and sample values.
--              Flag potentially sensitive metric names/values based on configurable regexes.
-- License: Same as Nmap
-- Categories: discovery, safe

local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local http      = require "http"
local json      = require "json"
local string    = require "string"
local table     = require "table"

description = [[
Fetches the Prometheus text exposition format from /metrics (and an optional custom path)
and produces:
  - a count of metric types (counter, gauge, histogram, summary)
  - a sample of metric names and latest sample values
  - flags for suspicious metric names or sample values (e.g., containing "token", "password", "secret")
Outputs human readable text by default or JSON when script-arg prometheus-metrics-audit.output=json
]]

author = "Arcanum Cyber Bot"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}

-- Default ports often used for HTTP/HTTPS metrics
portrule = shortport.port_or_service({80,443,9100,9102,9345,9216}, {"http", "https"})

-- helpers
local function split_lines(s)
  local t = {}
  for line in s:gmatch("([^\r\n]*)\r?\n?") do
    if line ~= "" then table.insert(t, line) end
  end
  return t
end

-- Parse a single line of Prometheus exposition format
-- returns {type="metric"/"meta", name=..., mtype=..., help=..., sample={name=...,labels=...,value=...}}
local function parse_metrics(text)
  local lines = split_lines(text or "")
  local metrics = {}
  local summary = {counts = {}, samples = {}, meta = {}}
  for _,line in ipairs(lines) do
    if line:match("^#%s*TYPE%s+") then
      local _,_,name,mtype = line:match("^#%s*TYPE%s+([%w_:.-]+)%s+([%w_]+)")
      if name and mtype then
        summary.counts[mtype] = (summary.counts[mtype] or 0) + 0  -- ensure key exists
        summary.meta[name] = summary.meta[name] or {}
        summary.meta[name].type = mtype
      end
    elseif line:match("^#%s*HELP%s+") then
      local _,_,name,help = line:match("^#%s*HELP%s+([%w_:.-]+)%s+(.+)")
      if name and help then
        summary.meta[name] = summary.meta[name] or {}
        summary.meta[name].help = help
      end
    else
      -- metric sample: name{labels} value timestamp?  OR name value
      local mname, rest = line:match("^([%w_:.-]+)%s*(.*)")
      if mname and rest then
        -- extract labels if present
        local labels_str, value = rest:match("^%s*%{(.-)%}%s+([%-%d.eE+]+)")
        if not labels_str then
          value = rest:match("^%s*([%-%d.eE+]+)")
        end
        local labels = {}
        if labels_str then
          for k,v in labels_str:gmatch('([%w_]+)%s*=%s*"(.-)"') do
            labels[k] = v
          end
        end
        summary.samples = summary.samples or {}
        summary.samples[mname] = summary.samples[mname] or {}
        -- store latest sample value (overwrite so last seen remains)
        table.insert(summary.samples[mname], {value = value, labels = labels})
      end
    end
  end
  return summary
end

-- default suspicious regex list; user can override via script-args
local default_name_regexes = {
  "pass",
  "passwd",
  "password",
  "secret",
  "token",
  "apikey",
  "api_key",
  "credential",
  "key_id",
  "auth",
  "private",
  "ssn",
  "card"
}

local function compile_regex_list(list)
  local patterns = {}
  for _,v in ipairs(list) do
    -- escape just in case? we'll treat as plain substring if simple token
    -- use case-insensitive matching
    local pat = v
    if pat:match("^[%w_%-]+$") then
      pat = "(?i)" .. pat -- attempt inline ignore-case; Lua patterns don't support (?i) though
      -- fallback: we'll lowercase both sides in checks
    end
    table.insert(patterns, v)
  end
  return patterns
end

local function name_matches_any(name, patterns)
  local lname = name:lower()
  for _,p in ipairs(patterns) do
    if lname:find(p:lower(), 1, true) then
      return true, p
    end
    -- allow simple Lua pattern if user provided one with special characters
    local ok, _, _ = p:find("[(%[].*[])]")
    -- don't attempt complex pattern matching by default; keep substring matching
  end
  return false, nil
end

-- Checks value string for evidence of secrets (very naive: long base64-like strings or tokens)
local function value_looks_like_secret(val)
  if not val then return false end
  -- common heuristics:
  -- 1) long (>30) base64-like
  if #val >= 30 and val:match("^[A-Za-z0-9%+/=]+$") then
    return true, "long-base64-like"
  end
  -- 2) contains "token=" or "bearer"
  if val:lower():find("token") or val:lower():find("bearer") then
    return true, "token-like"
  end
  -- 3) contains obvious key substrings
  if val:lower():find("key") or val:lower():find("secret") then
    return true, "keyword"
  end
  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args("prometheus-metrics-audit.path") or "/metrics"
  local out_format = stdnse.get_script_args("prometheus-metrics-audit.output") or "human"
  local name_patterns_arg = stdnse.get_script_args("prometheus-metrics-audit.name-patterns")
  local name_patterns = {}
  if name_patterns_arg then
    for tok in name_patterns_arg:gmatch("[^,]+") do
      table.insert(name_patterns, tok)
    end
  else
    name_patterns = default_name_regexes
  end

  -- request metrics (http.get will handle https when port.service indicates)
  local res, err = http.get(host, port, path)
  if not res then
    return stdnse.format_output(false, ("no response from %s%s: %s"):format(host.ip, path, err or "nil"))
  end

  local body = res.body or ""
  if body == "" then
    return stdnse.format_output(false, ("empty metrics body at %s%s"):format(host.ip, path))
  end

  local parsed = parse_metrics(body)
  -- build summary counts
  local metric_names = {}
  for name,_ in pairs(parsed.samples or {}) do
    table.insert(metric_names, name)
  end
  table.sort(metric_names)

  local flagged = {}
  for _,name in ipairs(metric_names) do
    local matched, pat = name_matches_any(name, name_patterns)
    if matched then
      flagged[name] = flagged[name] or {}
      table.insert(flagged[name], {reason = "name-pattern", pattern = pat})
    end
    -- check sample values for secret-like content
    for _,s in ipairs(parsed.samples[name] or {}) do
      local v = s.value
      local looks, reason = value_looks_like_secret(tostring(v))
      if looks then
        flagged[name] = flagged[name] or {}
        table.insert(flagged[name], {reason = "value-suspicious", detail = reason, sample = s})
      end
    end
  end

  -- prepare output
  if out_format == "json" then
    local j = {
      host = host.ip,
      port = port.number,
      path = path,
      metric_count = #metric_names,
      metrics = {},
      flagged = flagged
    }
    for _,n in ipairs(metric_names) do
      j.metrics[n] = {
        samples = parsed.samples[n] or {},
        meta = parsed.meta[n] or {}
      }
    end
    return json.encode(j)
  end

  -- human output
  local lines = {}
  table.insert(lines, ("Prometheus metrics audit for %s:%d%s"):format(host.ip, port.number, path))
  table.insert(lines, ("- Metric names discovered: %d"):format(#metric_names))
  local shown = 0
  for _,n in ipairs(metric_names) do
    if shown >= 30 then break end
    local sample = parsed.samples[n] and parsed.samples[n][#parsed.samples[n]] or nil
    local sval = sample and sample.value or "nil"
    table.insert(lines, ("  - %s = %s"):format(n, tostring(sval)))
    shown = shown + 1
  end
  if #metric_names > 30 then
    table.insert(lines, ("  ... (%d more metrics)"):format(#metric_names - 30))
  end

  if next(flagged) then
    table.insert(lines, "")
    table.insert(lines, "Suspicious metrics found:")
    for name,info in pairs(flagged) do
      table.insert(lines, ("- %s"):format(name))
      for _,i in ipairs(info) do
        if i.reason == "name-pattern" then
          table.insert(lines, ("    - reason: name matched pattern '%s'"):format(i.pattern))
        else
          table.insert(lines, ("    - reason: %s, detail: %s, sample value: %s"):format(i.reason, i.detail or "-", tostring(i.sample and i.sample.value or "-")))
        end
      end
    end
  else
    table.insert(lines, "")
    table.insert(lines, "No suspicious metrics detected with current heuristics.")
  end

  table.insert(lines, "")
  table.insert(lines, "Notes: This script performs a read-only GET on the metrics path. Confirm authorization before scanning production systems.")
  return stdnse.format_output(true, table.concat(lines, "\n"))
end
