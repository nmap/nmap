local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local nmap = require "nmap"

description = [[
Checks if a target is a known Tor node.

The script works by querying the Tor directory authorities. Initially,
the script stores all IPs of Tor nodes in a lookup table to reduce the
number of requests and make lookups quicker.
]]

---
-- @usage
-- nmap --script=tor-consensus-checker <host>
--
-- @output
-- Host script results:
-- | tor-consensus-checker:
-- |_  127.0.0.1 is a Tor node
---

author = "Jiayi Ye"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

-- from Tor 0.2.6.7/src/or/config.c
local dir_authorities = {
  { ip = "128.31.0.39", port = "9131"},
  { ip = "86.59.21.38", port = "80" },
  { ip = "194.109.206.212", port = "80" },
  { ip = "82.94.251.203", port = "80" },
  { ip = "131.188.40.189", port = "80"},
  { ip = "193.23.244.244", port = "80"},
  { ip = "208.83.223.34", port = "443" },
  { ip = "171.25.193.9", port = "443" },
  { ip = "154.35.175.225", port = "80" },
  { ip = "199.254.238.52", port = "80" }
}

hostrule = function(host)
  if nmap.registry.tornode and not(nmap.registry.tornode.connect) then
    return false
  end
  return not ipOps.isPrivate(host.ip)
end

function get_consensus(server)
  local response = http.get(server.ip, server.port, "/tor/status-vote/current/consensus")

  if not response.status then
    stdnse.print_debug(2, "failed to connect to " .. server.ip)
  elseif response.status ~= 200  then
    stdnse.print_debug(2, "%s http error %s", server.ip, response.status)
  else
    stdnse.print_debug(2, "consensus retrieved from %s", server.ip)
    return response.body
  end

  -- no valid server found
  return nil
end

function script_init()
  -- Data and flags shared between threads.
  -- @name tornode
  -- @class table
  -- @field cache     A table for cached tor nodes
  -- @field connect   A flag which prevents threads from looking up when failed to connnect to directory authorities
  nmap.registry.tornode = {}
  nmap.registry.tornode.cache = {}

  local isConnected = false
  local regexp = "r [%S]+ [%S]+ [%S]+ [%d-]+ [%d:]+ ([%d.]+) ([%d]+) [%d]*"
  for _, server in ipairs(dir_authorities) do
    local consensus = get_consensus(server)
    if consensus then
      isConnected = true
      -- parse the consensus
      for line in string.gmatch(consensus,"[^\n]+") do
        local _, _, ip, port = string.find(line,regexp)
        if ip then
          nmap.registry.tornode.cache[ip] = true
        end
      end
    end
  end
  if not(isConnected) then
    stdnse.verbose1("failed to connect to directory authorities")
  end
  nmap.registry.tornode.connect = isConnected
end

function check_tornode_cache(ip)
  if not next( nmap.registry.tornode.cache ) then return false end
  if type( ip ) ~= "string" or ip == "" then return false end
  return nmap.registry.tornode.cache[ip]
end

action = function(host)
  local mutex = nmap.mutex("tornode")
  mutex "lock"
  --initialize nmap.registry.tornode
  if not nmap.registry.tornode then
    script_init()
  end
  mutex "done"

  if not(nmap.registry.tornode.connect) then
    if nmap.verbosity() > 2 then
      return "Couln't connect to Tor dir authorities"
    else
      return nil
    end
  end

  local output_tab = stdnse.output_table()
  if check_tornode_cache(host.ip) then
    output_tab.tor_nodes = host.ip
    return output_tab, host.ip .. " is a Tor node"
  else
    return output_tab, host.ip .. " not found in Tor consensus"
  end
end
