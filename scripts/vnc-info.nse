local shortport = require "shortport"
local stdnse = require "stdnse"
local vnc = require "vnc"

description = [[
Queries a VNC server for its protocol version and supported security types.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT    STATE SERVICE
-- 5900/tcp open  vnc
-- | vnc-info:
-- |   Protocol version: 3.889
-- |   Security types:
-- |     Mac OS X security type (30)
-- |_    Mac OS X security type (35)
--
-- @xmloutput
-- <elem key="Protocol version">3.8</elem>
-- <table key="Security types">
--   <table>
--     <elem key="name">Ultra</elem>
--     <elem key="type">17</elem>
--   </table>
--   <table>
--     <elem key="name">VNC Authentication</elem>
--     <elem key="type">2</elem>
--   </table>
-- </table>

-- Version 0.2

-- Created 07/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 08/14/2010 - v0.2 - changed so that errors are reported even without debugging


portrule = shortport.port_or_service( {5900, 5901, 5902} , "vnc", "tcp", "open")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local vnc = vnc.VNC:new( host, port )
  local status, data
  local result = stdnse.output_table()

  status, data = vnc:connect()
  if ( not(status) ) then return fail(data) end

  status, data = vnc:handshake()
  if ( not(status) ) then return fail(data) end

  status, data = vnc:getSecTypesAsTable()
  if ( not(status) ) then return fail(data) end

  result["Protocol version"] = vnc:getProtocolVersion()

  if ( data and #data ~= 0 ) then
    result["Security types"] = data
  end

  if ( vnc:supportsSecType(vnc.sectypes.NONE) ) then
    result["WARNING"] = "Server does not require authentication"
  end

  return result
end
