--- Functions for communicating with Konnex (KNX) devices
--
-- @author Niklaus Schiess, Dominik Schneider
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name knx

local ipOps = require "ipOps"
local string = require "string"
local _ENV = {}

knxServiceFamilies = {
  [0x02]="KNXnet/IP Core",
  [0x03]="KNXnet/IP Device Management",
  [0x04]="KNXnet/IP Tunnelling",
  [0x05]="KNXnet/IP Routing",
  [0x06]="KNXnet/IP Remote Logging",
  [0x08]="KNXnet/IP Object Server",
  [0x07]="KNXnet/IP Remote Configuration and Diagnosis"
}

knxDibDescriptionTypes = {
  [0x01]="Device Information",
  [0x02]="Supp_Svc_families",
  [0x03]="IP_Config",
  [0x04]="IP_Cur_Config",
  [0x05]="IP_Config"
}

knxMediumTypes = {
  [0x01]="reserved",
  [0x02]="KNX TP1",
  [0x04]="KNX PL110",
  [0x08]="reserved",
  [0x10]="KNX RF",
  [0x20]="KNX IP"
}

--- Returns a raw knx request
-- @param service KNX service type of the request
-- @param ip_address IP address of the sending host
-- @param port Port where gateways should respond to
query = function(service, ip_address, port)
  return string.pack(">BB I2 I2 BB I4 I2",
    0x06, -- Header length
    0x10, -- Protocol version
    service, -- Service type
    0x000e, -- Total length
    0x08, -- Structure length
    0x01, -- Host protocol
    ipOps.todword(ip_address),
    port
  )
end

--- Parse a KNX address from raw bytes
-- @param addr Unpacked 2 bytes
-- @return KNX address in dotted-decimal format
parseKnxAddress = function(addr)
  local a = (addr & 0xf000) >> 12
  local b = (addr & 0x0f00) >>  8
  local c = addr & 0xff
  return a..'.'..b..'.'..c
end

--- Parse a KNX header
-- @param knxMessage A KNX message packet as a string
-- @return knx_header_length, or nil on error
-- @return knx_protocol_version, or error message
-- @return knx_service_type
-- @return knx_total_length
-- @return pos The position just after the header
parseHeader = function(knxMessage)
  if #knxMessage < 6 then
    return nil, "Message too short for KNX header"
  end
  local knx_header_length, knx_protocol_version, knx_service_type, knx_total_length, pos = string.unpack(">BB I2 I2", knxMessage)

  -- TODO: Should this be 'or' instead of 'and'?
  if knx_header_length ~= 0x06 and knx_protocol_version ~= 0x10 and  knx_service_type ~= 0x0204 then
    return nil, "Unknown KNX header format"
  end

  return knx_header_length, knx_protocol_version, knx_service_type, knx_total_length, pos
end

return _ENV
