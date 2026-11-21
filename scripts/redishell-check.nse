local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects potential exposure to CVE-2025-49844 (RediShell) by checking
the Redis server version and whether Lua scripting is reachable.
This script does NOT trigger the use-after-free condition and does
NOT send any exploit payload. Detection only.
]]

author = "Can Ünüvar (X-croot)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln", "discovery"}

portrule = shortport.port_or_service(6379, "redis")

local PATCHED = {
  ["6.2"] = 20,
  ["7.2"] = 11,
  ["7.4"] = 6,
  ["8.0"] = 4,
  ["8.2"] = 2,
}

local function is_vulnerable(ver)
  local major, minor, patch = ver:match("^(%d+)%.(%d+)%.(%d+)")
  if not major then
    return "unknown"
  end
  local key = major .. "." .. minor
  local min_patch = PATCHED[key]
  if not min_patch then
    return "unknown"
  end
  if tonumber(patch) < min_patch then
    return true
  end
  return false
end

action = function(host, port)
  local sock = nmap.new_socket()
  local status = sock:connect(host, port)
  if not status then
    return nil
  end

  sock:send("INFO server\r\n")
  local status2, response = sock:receive()
  if not status2 then
    sock:close()
    return nil
  end

  local version = response:match("redis_version:([%d%.]+)")
  if not version then
    sock:close()
    return "Redis version could not be determined"
  end

  sock:send("EVAL \"return 1\" 0\r\n")
  local status3, eval_resp = sock:receive()
  local scripting_enabled = status3 and eval_resp:match(":1") and true or false

  sock:close()

  local vuln_status = is_vulnerable(version)
  local out = stdnse.output_table()
  out.redis_version = version
  out.scripting_enabled = scripting_enabled

  if vuln_status == true and scripting_enabled then
    out.cve = "CVE-2025-49844 (RediShell)"
    out.state = "POTENTIALLY VULNERABLE - version below patch level, scripting reachable"
    out.recommendation = "Upgrade Redis or restrict EVAL/EVALSHA via ACL"
  elseif vuln_status == true then
    out.state = "Version below patch level but scripting not reachable - lower risk"
  else
    out.state = "Version patched or unrecognized"
  end

  return out
end
