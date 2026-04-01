---
-- A module implementing WCCP protocol (the code is a porting of:
-- https://github.com/benjamin-jones/wccpscan)
-- @class module
-- @name wccp
-- @author "Benjamin Jones <ben@benjaminjones.me>"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("wccp", stdnse.seeall)

WCCP2_HERE_I_AM = string.pack(">I4", 10)
WCCP2_I_SEE_YOU = string.pack(">I4", 11)
WCCP2_REDIRECT_ASSIGN = string.pack(">I4", 12)
WCCP2_REMOVAL_QUERY = string.pack(">I4", 13)

WCCP2_VERSION = string.pack(">H", 0x200)
WCCP2_SECURITY_INFO = string.pack(">H", 0)
WCCP2_NO_SECURITY = string.pack(">I4", 0)
WCCP2_SERVICE_INFO = string.pack(">H", 1)
WCCP2_SERVICE_STANDARD = string.pack(">B", 0)
WCCP2_WC_ID_INFO = string.pack(">H", 3)
WCCP2_WC_VIEW_INFO = string.pack(">H", 5)
WCCP2_REDIRECT_ASSIGN2 = string.pack(">H", 6)
WCCP2_ROUTER_ID_INFO = string.pack(">H", 2)
WCCP2_ROUTER_VIEW_INFO = string.pack(">H", 4)

function list_iter (t)
  local i = 0
  local n = #t
  return function ()
    i = i + 1
    if i <= n then return t[i] end
  end
end

ip_address = function(ip)
  -- convert IPv4 address to binary in network byte order
  local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
  local num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
  return string.pack(">I4", num)
end


wccp_web_cache_view_info_component = function(rip, ip)
  local mtype = WCCP2_WC_VIEW_INFO
  local change = string.pack(">I4", 1) 
  local nRouter = string.pack(">I4", 1) 
  local router_list = ip_address(rip)
  local rID = string.pack(">I4", 0xFFFFFFFF)
  local nCaches = string.pack(">I4", 1)
  local cache = ip_address(ip)
  local data = (
    change ..
    nRouter ..
    router_list ..
    rID ..
    nCaches ..
    cache
  )
  local length = string.pack(">H", string.len(data))
  local payload = mtype .. length .. data

  return payload
end

wccp_web_cache_identity_info_component = function(ip)
  local mtype = WCCP2_WC_ID_INFO
  local identity_element = ip_address(ip)
  local rht = string.pack(">I4", 0)
  for i=1,8 do
    rht = rht .. string.pack(">I4",0xFFFFFFFF)
  end
  rht = rht .. string.pack(">H", 10000)
  rht = rht .. string.pack(">H", 0)
  data = (
    identity_element ..
    rht
  )
  local length = string.pack(">H", string.len(data))
  local payload = (
    mtype .. length .. data
  )

  return payload 
end

wccp_service_info_component = function(sid, port_spec)
  local mtype = WCCP2_SERVICE_INFO
  local service_id = string.pack(">B", sid)
  local service_type = WCCP2_SERVICE_STANDARD 
  if service_id > WCCP2_SERVICE_STANDARD then
    service_type = string.pack(">B", 0x1) -- Dynamic service
  end

  local priority = string.pack(">B", 0)
  local mprotocol = 0x0 -- IPv6 (will give everything!)
  local ports_defined = 0
  local dest_port_hash = 0
  local redirect_only = 0

  if port_spec ~= nil then 
      mprotocol = 0x06 -- TCP
      ports_defined = 0x10
      dest_port_hash = 0x08
      redirect_only = 0x40
  end

  local protocol = string.pack(">B", mprotocol)
  local service_flags = string.pack(">I4",0+ports_defined+redirect_only+dest_port_hash)

  local ports = ""
  if port_spec ~= nil then
    for port in list_iter(port_spec) do
      ports = ports .. string.pack(">H", port)
    end
  else
    for i=1,8 do
      ports = ports .. string.pack(">H", 0x0)
    end
  end

  local data = (
    service_type ..
    service_id ..
    priority ..
    protocol ..
    service_flags .. 
    ports
  )
  local length = string.pack(">H", string.len(data))
  local payload = (
    mtype .. length .. data
  )

  return payload 
end

wccp_security_component = function()
  local mtype = WCCP2_SECURITY_INFO
  local option = WCCP2_NO_SECURITY

  local data = (
      option
  )
  local length = string.pack(">H", string.len(data))
  local security_component = (
    mtype ..
    length ..
    data
  )

  return security_component
end


wccp_hia_header = function(message)
  local mtype = WCCP2_HERE_I_AM
  local version = WCCP2_VERSION
  local data = message
  local length = string.pack(">H", string.len(data))
  local header = (
    mtype ..
    version .. 
    length .. 
    data
  )
    
  return header 
end

wccp_hia_message = function(rip, ip, sid, port_spec)
  local security = wccp_security_component()
  local service_info = wccp_service_info_component(sid, port_spec)
  local identity_info = wccp_web_cache_identity_info_component(ip)
  local view_info = wccp_web_cache_view_info_component(rip, ip)

  local msg = ( 
    security ..
    service_info ..
    identity_info ..
    view_info
  )

  return wccp_hia_header(msg)
end

wccp_parse_isy = function(reply)
  local data = {}
  local pos = 1

  data.mtype, data.version = string.unpack("=IH", reply, pos)
  stdnse.debug1(string.format("type=%x version=%x", data.mtype, data.version))
  if data.mtype ~= 0xb000000 then
    return nil
  end

  if data.version ~= 0x2 then
    return nil
  end

  return true
end

return _ENV;

