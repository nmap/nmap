local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to discover DB2 servers on the network by sending a broadcast request to port 523/udp.
]]

---
-- @usage
-- nmap --script db2-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-db2-discover:
-- |   10.0.200.132 (UBU804-DB2E) - IBM DB2 v9.07.0
-- |_  10.0.200.119 (EDUSRV011) - IBM DB2 v9.07.0

-- Version 0.1
-- Created 07/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

--- Converts the prodrel server string to a version string
--
-- @param server_version string containing the product release
-- @return ver string containing the version information
local function parseVersion( server_version )
  local pfx = string.sub(server_version,1,3)

  if pfx == "SQL" then
    local major_version = string.sub(server_version,4,5)

    -- strip the leading 0 from the major version, for consistency with
    -- nmap-service-probes results
    if string.sub(major_version,1,1) == "0" then
      major_version = string.sub(major_version,2)
    end
    local minor_version = string.sub(server_version,6,7)
    local hotfix = string.sub(server_version,8)
    server_version = major_version .. "." .. minor_version .. "." .. hotfix
  else
    return "Unknown version"
  end

  return ("IBM DB2 v%s"):format(server_version)
end

action = function()

  local DB2GETADDR = "DB2GETADDR\0SQL09010\0"
  local socket = nmap.new_socket("udp")
  local result = {}
  local host, port = "255.255.255.255", 523

  socket:set_timeout(5000)
  local status = socket:sendto( host, port, DB2GETADDR )
  if ( not(status) ) then return end

  while(true) do
    local data
    status, data = socket:receive()
    if( not(status) ) then break end

    local version, srvname = data:match("DB2RETADDR.(SQL%d+).(.-)\0")
    local _, ip
    status, _, _, ip, _ = socket:get_info()
    if ( not(status) ) then return end

    if target.ALLOW_NEW_TARGETS then target.add(ip) end

    if ( status ) then
      table.insert( result, ("%s - Host: %s; Version: %s"):format(ip, srvname, parseVersion( version ) )  )
    end
  end
  socket:close()

  return stdnse.format_output( true, result )
end
