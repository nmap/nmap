local nmap = require "nmap"
local shortport = require "shortport"
local bin = require "bin"
local bit = require "bit"
local ipOps = require "ipOps"
local stdnse = require "stdnse"

description = [[
Identifies a KNX gateway on UDP port 3671 by sending a KNX Description Request.

Further information:
  * DIN EN 13321-2
  * http://www.knx.org/
]]

author = "Niklaus Schiess <nschiess@ernw.de>, Dominik Schneider <dschneider@ernw.de>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
portrule = shortport.port_or_service(3671, "efcp", "udp")

---
--@output
-- 3671/udp open|filtered efcp
-- | knx-gateway-info:
-- |   Body:
-- |     DIB_DEV_INFO:
-- |       KNX address: 15.15.255
-- |       Decive serial: 00ef2650065c
-- |       Multicast address: 0.0.0.0
-- |       Device friendly name: IP-Viewer
-- |     DIB_SUPP_SVC_FAMILIES:
-- |       KNXnet/IP Core version 1
-- |       KNXnet/IP Device Management version 1
-- |       KNXnet/IP Tunneling version 1
-- |_      KNXnet/IP Object Server version 1
--

local knxServiceFamilies = {
  [0x02]="KNXnet/IP Core",
  [0x03]="KNXnet/IP Device Management",
  [0x04]="KNXnet/IP Tunneling",
  [0x05]="KNXnet/IP Routing",
  [0x06]="KNXnet/IP Remote Logging",
  [0x08]="KNXnet/IP Object Server",
  [0x07]="KNXnet/IP Remote Configuration and Diagnosis"
}

local knxDibDescriptionTypes = {
  [0x01]="Device Information",
  [0x02]="Supp_Svc_families",
  [0x03]="IP_Config",
  [0x04]="IP_Cur_Config",
  [0x05]="IP_Config"
}

local knxMediumTypes = {
  [0x01]="reserved",
  [0x02]="KNX TP1",
  [0x04]="KNX PL110",
  [0x08]="reserved",
  [0x10]="KNX RF",
  [0x20]="KNX IP"
}

--- Returns a raw knx description request
-- @param ip_address IP address of the sending host
-- @param port Port where gateways sends response packets to
local knxQuery = function(ip_address, port)
  return bin.pack(">C2S2C2IS",
    0x06, -- Header length
    0x10, -- Protocol version
    0x0203, -- Service type
    0x000e, -- Total length
    0x08, -- Structure length
    0x01, -- Host protocol
    ipOps.todword(ip_address),
    port
  )
end

-- Parse a KNX address from raw bytes
-- @param addr Unpacked 2 bytes
local parseKnxAddress = function(addr)
  local a = bit.rshift(bit.band(addr, 0xf000),12)
  local b = bit.rshift(bit.band(addr, 0x0f00), 8)
  local c = bit.band(addr, 0xff)
  return a..'.'..b..'.'..c
end

local fam_meta = {
  __tostring = function (self)
    return ("%s version %d"):format(
      knxServiceFamilies[self.service_id] or self.service_id,
      self.Version
      )
  end
}

--- Parse a Description Response
-- @param knxMessage UDP response packet
local knxParseDescriptionResponse = function(knxMessage)
  local _, knx_header_length =  bin.unpack('>C', knxMessage)
  local _, knx_protocol_version = bin.unpack('>C', knxMessage, _)
  local _, knx_service_type = bin.unpack('>S', knxMessage, _)
  local _, knx_total_length = bin.unpack('>S', knxMessage, _)

  if knx_header_length ~= 0x06 and knx_protocol_version ~= 0x10 and  knx_service_type ~= 0x0204 then
    return
  end

  local _, knx_dib_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_dib_description_type = bin.unpack('>C', knxMessage, _)
  knx_dib_description_type = knxDibDescriptionTypes[knx_dib_description_type]
  local _, knx_dib_knx_medium = bin.unpack('>C', knxMessage, _)
  knx_dib_knx_medium = knxMediumTypes[knx_dib_knx_medium]
  local _, knx_dib_device_status = bin.unpack('>A1', knxMessage, _)
  local _, knx_dib_knx_address = bin.unpack('>S', knxMessage, _)
  local _, knx_dib_project_install_ident = bin.unpack('>A2', knxMessage, _)
  local _, knx_dib_dev_serial = bin.unpack('>A6', knxMessage, _)
  local _, knx_dib_dev_multicast_addr = bin.unpack('>A4', knxMessage, _)
  knx_dib_dev_multicast_addr = ipOps.str_to_ip(knx_dib_dev_multicast_addr)
  local _, knx_dib_dev_mac = bin.unpack('>A6', knxMessage, _)
  knx_dib_dev_mac = stdnse.format_mac(knx_dib_dev_mac)
  local _, knx_dib_dev_friendly_name = bin.unpack('>A30', knxMessage, _)

  local knx_supp_svc_families = {}
  local _, knx_supp_svc_families_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_supp_svc_families_description = bin.unpack('>C', knxMessage, _)
  knx_supp_svc_families_description = knxDibDescriptionTypes[knx_supp_svc_families_description] or knx_supp_svc_families_description

  for i=0,(knx_total_length-_),2 do
    local family = {}
    _, family.service_id, family.Version = bin.unpack('CC', knxMessage, _)
    setmetatable(family, fam_meta)
    knx_supp_svc_families[#knx_supp_svc_families+1] = family
  end

  --Build a proper response table
  local description_response = stdnse.output_table()
  if nmap.debugging() > 0 then
    description_response.Header = stdnse.output_table()
    description_response.Header["Header length"] = knx_header_length
    description_response.Header["Protocol version"] = knx_protocol_version
    description_response.Header["Service type"] = "DESCRIPTION_RESPONSE (0x0204)"
    description_response.Header["Total length"] = knx_total_length

    description_response.Body = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO["Description type"] = knx_dib_description_type
    description_response.Body.DIB_DEV_INFO["KNX medium"] = knx_dib_knx_medium
    description_response.Body.DIB_DEV_INFO["Device status"] = stdnse.tohex(knx_dib_device_status)
    description_response.Body.DIB_DEV_INFO["KNX address"] = parseKnxAddress(knx_dib_knx_address)
    description_response.Body.DIB_DEV_INFO["Project installation identifier"] = stdnse.tohex(knx_dib_project_install_ident)
    description_response.Body.DIB_DEV_INFO["Decive serial"] = stdnse.tohex(knx_dib_dev_serial)
    description_response.Body.DIB_DEV_INFO["Multicast address"] = knx_dib_dev_multicast_addr
    description_response.Body.DIB_DEV_INFO["Device MAC address"] = knx_dib_dev_mac
    description_response.Body.DIB_DEV_INFO["Device friendly name"] = knx_dib_dev_friendly_name
    description_response.Body.DIB_SUPP_SVC_FAMILIES = knx_supp_svc_families
  else
    description_response.Body = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO["KNX address"] = parseKnxAddress(knx_dib_knx_address)
    description_response.Body.DIB_DEV_INFO["Decive serial"] = stdnse.tohex(knx_dib_dev_serial)
    description_response.Body.DIB_DEV_INFO["Multicast address"] = knx_dib_dev_multicast_addr
    description_response.Body.DIB_DEV_INFO["Device friendly name"] = knx_dib_dev_friendly_name
    description_response.Body.DIB_SUPP_SVC_FAMILIES = knx_supp_svc_families
  end

  return description_response
end

action = function(host, port)
  local sock = nmap.new_socket()
  local status, err = sock:connect(host, port)

  if not status then
    stdnse.debug1("Connect failed: %s", err)
    return
  end

  local _, lhost, lport, _, _ = sock:get_info()
  sock:send(knxQuery(lhost, lport))
  local status, data = sock:receive()

  if not status then
    stdnse.debug("Receive failed: %s", err)
    sock:close()
    return
  end

  sock:close()
  return knxParseDescriptionResponse(data)
end
