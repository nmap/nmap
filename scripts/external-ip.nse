-- external-ip.nse

local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local math = require "math"
local target = require "target"

description = [[
Queries a randomly selected external IP provider to determine the public-facing
IP address of the local (scanning) machine. Useful for verifying your egress
address before running scans.

If called with --script-args=newtargets, the discovered external IP will be
added to nmap's target list for scanning.
]]

---
-- @usage
-- nmap --script external-ip
-- nmap --script external-ip --script-args=newtargets
--
-- @output
-- Pre-scan script results:
-- | external-ip:
-- |   external_ip: 203.0.113.42
-- |_  added_to_targets: true

author = "AI"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe", "discovery"}

prerule = function()
  return true
end

local providers = {
  {
    name = "ipify",
    url  = "api.ipify.org",
    path = "/",
  },
  {
    name = "icanhazip",
    url  = "icanhazip.com",
    path = "/",
  },
  {
    name = "ifconfig.me",
    url  = "ifconfig.me",
    path = "/ip",
  },
  {
    name = "ipinfo.io",
    url  = "ipinfo.io",
    path = "/ip",
  },
  {
    name = "checkip.amazonaws.com",
    url  = "checkip.amazonaws.com",
    path = "/",
  },
  {
    name = "wtfismyip",
    url  = "wtfismyip.com",
    path = "/text",
  },
  {
    name = "ip.me",
    url  = "ip.me",
    path = "/",
  },
}

local function pick_random_provider()
  math.randomseed(os.time())
  local idx = math.random(1, #providers)
  return providers[idx]
end

local function trim(s)
  return s:match("^%s*(.-)%s*$")
end

action = function()
  local provider = pick_random_provider()
  local full_url = "https://" .. provider.url .. provider.path

  stdnse.debug1("querying provider: %s (%s)", provider.name, full_url)

  local response = http.get(provider.url, 443, provider.path, {
    scheme = "https",
    header = {
      ["User-Agent"] = "curl/8.0",
      ["Accept"]     = "text/plain",
    },
  })

  if not response or not response.status then
    return stdnse.format_output(false,
      ("no response from %s"):format(provider.name))
  end

  if response.status ~= 200 then
    return stdnse.format_output(false,
      ("provider %s returned HTTP %d"):format(provider.name, response.status))
  end

  local ip = trim(response.body or "")

  if ip == "" then
    return stdnse.format_output(false,
      ("empty response from %s"):format(provider.name))
  end

  -- basic sanity check: looks like an ipv4 or ipv6 address
  if not ip:match("^%d+%.%d+%.%d+%.%d+$") and not ip:match(":") then
    return stdnse.format_output(false,
      ("unexpected response from %s: %s"):format(provider.name, ip))
  end

  -- add to target list if newtargets is enabled
  local added = false
  if target.ALLOW_NEW_TARGETS then
    added = target.add(ip)
    if added then
      stdnse.debug1("added %s to target list", ip)
    else
      stdnse.debug1("failed to add %s to target list", ip)
    end
  end

  local output = stdnse.output_table()
  output.provider = full_url
  output.external_ip = ip

  if target.ALLOW_NEW_TARGETS then
    output.added_to_targets = added
  end

  return output
end
