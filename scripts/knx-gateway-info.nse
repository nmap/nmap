local nmap = require "nmap"
local shortport = require "shortport"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local knx = require "knx"

description = [[
Identifies a KNX gateway on UDP port 3671 by sending a KNX Description Request.

Further information:
  * DIN EN 13321-2
  * http://www.knx.org/
]]

author = {"Niklaus Schiess <nschiess@ernw.de>", "Dominik Schneider <dschneider@ernw.de>"}
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


local fam_meta = {
  __tostring = function (self)
    return ("%s version %d"):format(
      knx.knxServiceFamilies[self.service_id] or self.service_id,
      self.Version
      )
  end
}

--- Parse a Description Response
-- @param knxMessage UDP response packet
local knxParseDescriptionResponse = function(knxMessage)
  local knx_header_length, knx_protocol_version, knx_service_type, knx_total_length, pos = knx.parseHeader(knxMessage)

  if not knx_header_length then
    stdnse.debug1("KNX header error: %s", knx_protocol_version)
    return
  end

  local message_format = '>BBB c1 I2 c2 c6 c4 c6 c30 BB'
  if #knxMessage - pos + 1 < string.packlen(message_format) then
    stdnse.debug1("Message too short for KNX message")
    return
  end

  local knx_dib_structure_length,
  knx_dib_description_type,
  knx_dib_knx_medium,
  knx_dib_device_status,
  knx_dib_knx_address,
  knx_dib_project_install_ident,
  knx_dib_dev_serial,
  knx_dib_dev_multicast_addr,
  knx_dib_dev_mac,
  knx_dib_dev_friendly_name,
  knx_supp_svc_families_structure_length,
  knx_supp_svc_families_description, pos = string.unpack(message_format, knxMessage, pos)

  knx_dib_description_type = knx.knxDibDescriptionTypes[knx_dib_description_type]
  knx_dib_knx_medium = knx.knxMediumTypes[knx_dib_knx_medium]
  knx_dib_dev_multicast_addr = ipOps.str_to_ip(knx_dib_dev_multicast_addr)
  knx_dib_dev_mac = stdnse.format_mac(knx_dib_dev_mac)

  local knx_supp_svc_families = {}
  knx_supp_svc_families_description = knx.knxDibDescriptionTypes[knx_supp_svc_families_description] or knx_supp_svc_families_description

  for i=0,(knx_total_length - pos),2 do
    local family = {}
    family.service_id, family.Version, pos = string.unpack('BB', knxMessage, pos)
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
    description_response.Body.DIB_DEV_INFO["KNX address"] = knx.parseKnxAddress(knx_dib_knx_address)
    description_response.Body.DIB_DEV_INFO["Project installation identifier"] = stdnse.tohex(knx_dib_project_install_ident)
    description_response.Body.DIB_DEV_INFO["Decive serial"] = stdnse.tohex(knx_dib_dev_serial)
    description_response.Body.DIB_DEV_INFO["Multicast address"] = knx_dib_dev_multicast_addr
    description_response.Body.DIB_DEV_INFO["Device MAC address"] = knx_dib_dev_mac
    description_response.Body.DIB_DEV_INFO["Device friendly name"] = knx_dib_dev_friendly_name
    description_response.Body.DIB_SUPP_SVC_FAMILIES = knx_supp_svc_families
  else
    description_response.Body = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO = stdnse.output_table()
    description_response.Body.DIB_DEV_INFO["KNX address"] = knx.parseKnxAddress(knx_dib_knx_address)
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
  sock:send(knx.query(0x0203, lhost, lport))
  local status, data = sock:receive()

  if not status then
    stdnse.debug("Receive failed: %s", err)
    sock:close()
    return
  end

  sock:close()
  return knxParseDescriptionResponse(data)
end
