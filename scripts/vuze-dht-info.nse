local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local vuzedht = stdnse.silent_require "vuzedht"

description = [[
Retrieves some basic information, including protocol version from a Vuze filesharing node.

As Vuze doesn't have a default port for its DHT service, this script has
some difficulties in determining when to run. Most scripts are triggered by
either a default port or a fingerprinted service. To get around this, there
are two options:
1. Always run a version scan, to identify the vuze-dht service in order to
   trigger the script.
2. Force the script to run against each port by setting the argument
   vuze-dht-info.allports
]]

---
-- @usage
-- nmap -sU -p <port> <ip> --script vuze-dht-info -sV
--
-- @output
-- PORT      STATE SERVICE  VERSION
-- 17555/udp open  vuze-dht Vuze
-- | vuze-dht-info:
-- |   Transaction id: 9438865
-- |   Connection id: 0xFF79A77B4592BDB0
-- |   Protocol version: 50
-- |   Vendor id: Azureus (0)
-- |   Network id: Stable (0)
-- |_  Instance id: 2260473691
--
-- @args vuze-dht-info.allports if set runs this script against every open port

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = function(host, port)
  local allports = stdnse.get_script_args('vuze-dht-info.allports')
  if ( tonumber(allports) == 1 or allports == 'true' ) then
    return true
  else
    local f = shortport.port_or_service({17555, 49160, 49161, 49162}, "vuze-dht", "udp", {"open", "open|filtered"})
    return f(host, port)
  end
end

local function getDHTInfo(host, port, lhost)

  local helper = vuzedht.Helper:new(host, port, lhost)
  local status = helper:connect()

  if ( not(status) ) then
    return false, "Failed to connect to server"
  end

  local response
  status, response = helper:ping()
  if ( not(status) ) then
    return false, "Failed to ping vuze node"
  end
  helper:close()

  return true, response
end

action = function(host, port)

  local status, response = getDHTInfo(host, port)
  if not status then
    return stdnse.format_output(false, response)
  end

  -- check whether we have an error due to an incorrect address
  -- ie. we're on a NAT:ed network and we're announcing our private ip
  if ( status and response.header.action == vuzedht.Response.Actions.ERROR  ) then
    status, response = getDHTInfo(host, port, response.addr.ip)
  end

  if ( status ) then
    nmap.set_port_state(host, port, "open")
    return tostring(response)
  end
end
