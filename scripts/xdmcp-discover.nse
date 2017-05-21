local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local xdmcp = require "xdmcp"

description = [[
Requests an XDMCP (X display manager control protocol) session and lists supported authentication and authorization mechanisms.
]]

---
-- @usage
-- nmap -sU -p 177 --script xdmcp-discover <ip>
--
-- @output
-- PORT    STATE         SERVICE
-- 177/udp open|filtered xdmcp
-- | xdmcp-discover:
-- |   Session id: 0x0000703E
-- |   Authorization name: MIT-MAGIC-COOKIE-1
-- |_  Authorization data: c282137c9bf8e2af88879e6eaa922326
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


portrule = shortport.port_or_service(177, "xdmcp", "udp")

local mutex = nmap.mutex("xdmcp-discover")
local function fail(err) return stdnse.format_output(false, err) end


action = function(host, port)

  local DISPLAY_ID = 1
  local result = {}

  local helper = xdmcp.Helper:new(host, port)
  local status = helper:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, response = helper:createSession(nil,
    {"MIT-MAGIC-COOKIE-1", "XDM-AUTHORIZATION-1"}, DISPLAY_ID)

  if ( not(status) ) then
    return fail("Failed to create xdmcp session")
  end

  table.insert(result, ("Session id: 0x%.8X"):format(response.session_id))
  if ( response.auth_name and 0 < #response.auth_name ) then
    table.insert(result, ("Authentication name: %s"):format(response.auth_name))
  end
  if ( response.auth_data and 0 < #response.auth_data ) then
    table.insert(result, ("Authentication data: %s"):format(stdnse.tohex(response.auth_data)))
  end
  if ( response.authr_name and 0 < #response.authr_name ) then
    table.insert(result, ("Authorization name: %s"):format(response.authr_name))
  end
  if ( response.authr_data and 0 < #response.authr_data ) then
    table.insert(result, ("Authorization data: %s"):format(stdnse.tohex(response.authr_data)))
  end
  return stdnse.format_output(true, result)
end
