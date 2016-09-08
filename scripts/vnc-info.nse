local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
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

  local v = vnc.VNC:new( host, port )
  local status, data
  local result = stdnse.output_table()

  status, data = v:connect()
  if ( not(status) ) then return fail(data) end

  status, data = v:handshake()
  if ( not(status) ) then return fail(data) end

  data = v:getSecTypesAsTable()

  result["Protocol version"] = v:getProtocolVersion()

  if ( data and #data ~= 0 ) then
    result["Security types"] = data
  end

  local none_auth = false
  if ( v:supportsSecType(v.sectypes.NONE) ) then
    none_auth = true
  end

  if v:supportsSecType(v.sectypes.VENCRYPT) then
    v:sendSecType(v.sectypes.VENCRYPT)
    status, data = v:handshake_vencrypt()
    if not status then
      stdnse.debug1("Failed to handshake VeNCrypt: %s", data)
    else
      result["VeNCrypt auth subtypes"] = v:getVencryptTypesAsTable()
      if not none_auth then
        for i=1, v.vencrypt.count do
          if v.vencrypt.types[i] == vnc.VENCRYPT_SUBTYPES.TLSNONE or
            v.vencrypt.types[i] == vnc.VENCRYPT_SUBTYPES.TLSNONE then
            none_auth = true
            break
          end
        end
      end
    end
    -- Reset the connection for further tests
    v:disconnect()
  end

  if v:supportsSecType(v.sectypes.TIGHT) then
    if not v.socket:get_info() then
      -- reconnect if necessary
      v:connect()
      v:handshake()
    end
    v:sendSecType(v.sectypes.TIGHT)
    status, data = v:handshake_tight()
    if not status then
      stdnse.debug1("Failed to handshake Tight: %s", data)
    else
      local mt = {
        __tostring = function(t)
          return string.format("%s %s (%d)", t.vendor, t.signature, t.code)
        end
      }
      local tunnels = {}
      for _, t in ipairs(v.tight.tunnels) do
        setmetatable(t, mt)
        tunnels[#tunnels+1] = t
      end
      if #tunnels > 0 then
        result["Tight auth tunnels"] = tunnels
      end
      if #v.tight.types == 0 then
        none_auth = true
        result["Tight auth subtypes"] = {"None"}
      else
        local subtypes = {}
        for _, t in ipairs(v.tight.types) do
          if t.code == 1 then
            none_auth = true
          end
          setmetatable(t, mt)
          subtypes[#subtypes+1] = t
        end
        result["Tight auth subtypes"] = subtypes
      end
    end
    -- Reset the connection for further tests
    v:disconnect()
  end

  if v:supportsSecType(v.sectypes.TLS) then
    if not v.socket:get_info() then
      -- reconnect if necessary
      v:connect()
      v:handshake()
    end
    v:sendSecType(v.sectypes.TLS)
    status, data = v:handshake_tls()
    if not status then
      stdnse.debug1("Failed to handshake TLS: %s", data)
    else
      result["TLS auth subtypes"] = v:getSecTypesAsTable()
      if v:supportsSecType(v.sectypes.NONE) then
        none_auth = true
      end
    end
  end

  if none_auth then
    result["WARNING"] = "Server does not require authentication"
  end

  return result
end
