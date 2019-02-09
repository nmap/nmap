local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local ipOps = require "ipOps"
local tableaux = require "tableaux"

description = [[
Extracts information from Ubiquiti networking devices.

This script leverages Ubiquiti's Discovery Service which is enabled by default
on many products. It will attempt to leverage version 1 of the protocol first
and, if that fails, attempt version 2.
]]

author = {"Tom Sellers"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "version", "safe"}

---
-- @usage
-- nmap -sU -p 10001 --script ubiquiti-discovery.nse <target>
--
---
-- @output
-- PORT      STATE SERVICE            VERSION
-- 10001/udp open  ubiquiti-discovery Ubiquiti Discovery Service (v1 protocol, ER-X software ver. v1.10.7)
-- | ubiquiti-discovery:
-- |   protocol: v1
-- |   uptime_seconds: 113144
-- |   uptime: 1 days 07:25:44
-- |   hostname: ubnt-router
-- |   product: ER-X
-- |   firmware: EdgeRouter.ER-e50.v1.10.7.5127989.181001.1227
-- |   version: v1.10.7
-- |   interface_to_ip:
-- |     80:2a:a8:ae:f1:63:
-- |       192.168.0.1
-- |       172.25.16.1
-- |     80:2a:a8:ae:f1:5e:
-- |       55.55.55.10
-- |       55.55.55.11
-- |       55.55.55.12
-- |   mac_addresses:
-- |     80:2a:a8:ae:f1:63
-- |_    80:2a:a8:ae:f1:5e
--
-- PORT      STATE SERVICE            REASON       VERSION
-- 10001/udp open  ubiquiti-discovery udp-response Ubiquiti Discovery Service (v2 protocol, UCK-v2 software ver. 5.9.29)
-- | ubiquiti-discovery:
-- |   protocol: v2
-- |   firmware: UCK.mtk7623.v0.12.0.29a26c9.181001.1444
-- |   version: 5.9.29
-- |   model: UCK-v2
-- |   config_status: managed/adopted
-- |   interface_to_ip:
-- |     78:8a:20:21:ae:7b:
-- |       192.168.0.30
-- |   mac_addresses:
-- |_    78:8a:20:21:ae:7b
--
--@xmloutput
-- <elem key="protocol">v1</elem>
-- <elem key="uptime_seconds">113144</elem>
-- <elem key="uptime">1 days 07:25:44</elem>
-- <elem key="hostname">ubnt-router</elem>
-- <elem key="product">ER-X</elem>
-- <elem key="firmware">EdgeRouter.ER-e50.v1.10.7.5127989.181001.1227</elem>
-- <elem key="version">v1.10.7</elem>
-- <table key="interface_to_ip">
-- <table key="80:2a:a8:ae:f1:63">
--   <elem>192.168.0.1</elem>
--   <elem>172.25.16.1</elem>
-- </table>
--   <table key="80:2a:a8:ae:f1:5e">
--    <elem>55.55.55.10</elem>
--    <elem>55.55.55.11</elem>
--    <elem>55.55.55.12</elem>
--   </table>
-- </table>
-- <table key="mac_addresses">
--   <elem>80:2a:a8:ae:f1:63</elem>
--   <elem>80:2a:a8:ae:f1:5e</elem>
-- </table>
--
-- <elem key="protocol">v2</elem>
-- <elem key="version">5.9.29</elem>
-- <elem key="model">UCK-v2</elem>
-- <elem key="config_status">managed/adopted</elem>
-- <table key="interface_to_ip">
--   <table key="78:8a:20:21:ae:7b">
--     <elem>192.168.0.30</elem>
--   </table>
-- </table>
-- <table key="mac_addresses">
--   <elem>78:8a:20:21:ae:7b</elem>
-- </table>
--


portrule = shortport.port_or_service(10001, "ubiquiti-discovery", "udp", {"open", "open|filtered"})

local PROBE_V1 = string.pack("BB I2",
  0x01, 0x00, -- version, command
  0x00, 0x00  -- length
)

local PROBE_V2 = string.pack("BB I2",
  0x02, 0x08, -- version, command
  0x00, 0x00  -- length
)
---
-- Converts uptime seconds into a human readable string
--
-- E.g. "86518" -> "1 days 00:01:58"
--
-- @param uptime number of seconds of uptime
-- @return formatted uptime string (days, hours, minutes, seconds)
local function uptime_str(uptime)
  if not uptime then
    return nil
  end

  local d = uptime // 86400
  local h = uptime //  3600 % 24
  local m = uptime //    60 % 60
  local s = uptime % 60

  return string.format("%d days %02d:%02d:%02d", d, h, m, s)
end

---
-- Parses the full payload of a discovery response
--
-- There are different fields for v1 and v2 of the protocol but as far as I can
-- tell they don't conflict so we should be safe parsing them both with the same
-- code as long as we sanity check the version and cmd.
--
-- @param payload containing response
-- @return output_table containing results or nil
local function parse_discovery_response(response)

  local info = stdnse.output_table()
  local unique_macs = {}
  local mac_ip_table = {}

  if #response < 4 then
    return nil
  end

  -- Verify header and cmd
  if response:byte(1) == 0x01 then
    if response:byte(2) ~= 0x00 then
      return nil
    end
    info.protocol = "v1"
  elseif response:byte(1) == 0x02 then
    -- Known values for cmd are 6,9, and 11
    if response:byte(2) ~= 0x06 and response:byte(2) ~= 0x09
        and response:byte(2) ~= 0x0b then

      return nil
    end
    info.protocol = "v2"
  else
    return nil
  end

  local config_len = string.unpack(">I2", response, 3)

  -- Do the lengths check out?
  if ( not ( #response == config_len + 4) ) then
    return nil
  end

  -- Response looks legit, start extraction
  local config_data = string.sub(response, 5, #response)

  local tlv_type, tlv_len, tlv_value, pos
  local mac, mac_raw, ip, ip_raw
  pos = 1

  while pos <= #config_data - 2 do
    tlv_type = config_data:byte(pos)
    tlv_len  = string.unpack(">I2", config_data, pos +1)
    pos = pos + 3

    -- Sanity check that TLV len isn't larger than the data we have left.
    -- Has been observed in the wild against protocols just similar enough to
    -- make it here.
    if tlv_len > (#config_data - pos + 1) then
      return nil
    end

    tlv_value = config_data:sub(pos, pos + tlv_len - 1)

    -- MAC address
    if tlv_type == 0x01 then
      mac_raw = tlv_value:sub(1, 6)
      mac = stdnse.format_mac(mac_raw)
      unique_macs[mac] = true

    -- MAC and IP address
    elseif tlv_type == 0x02 then
      mac_raw = tlv_value:sub(1, 6)
      mac = stdnse.format_mac(mac_raw)
      unique_macs[mac] = true

      ip_raw = tlv_value:sub(7, tlv_len)
      ip = ipOps.str_to_ip(ip_raw)
      if mac_ip_table[mac] == nil then
        mac_ip_table[mac] = {}
      end
      mac_ip_table[mac][ip] = true

    elseif tlv_type == 0x03 then
      info.firmware = tlv_value

      local human_version = tlv_value:match("%.(v%d+%.%d+%.%d+)")
      if human_version then
        info.version = human_version
      end

    elseif tlv_type == 0x0a then
      if tlv_len == 4 then
        local uptime_raw = string.unpack(">I4", tlv_value)
        info.uptime_seconds = uptime_raw
        info.uptime = uptime_str(uptime_raw)
      end

    elseif tlv_type == 0x0b then
      info.hostname = tlv_value

    elseif tlv_type == 0x0c then
      info.product = tlv_value

    elseif tlv_type == 0x0d then
      info.essid = tlv_value

    elseif tlv_type == 0x0f then
      -- value also includes bit shifted flag for http vs https but we
      -- are ignoring it here.
      if tlv_len == 4 then
        tlv_value = string.unpack(">I4", tlv_value)
        info.mgmt_port = tlv_value & 0xffff
      end

    -- model v1 protocol
    elseif tlv_type == 0x14 then
      info.model = tlv_value

    -- model v2 protocol
    elseif tlv_type == 0x15 then
      info.model = tlv_value

    elseif tlv_type == 0x16 then
      info.version = tlv_value

    elseif tlv_type == 0x17 then
      local is_default
      if tlv_len == 4 then
        is_default = string.unpack("I4", tlv_value)
      elseif tlv_len == 1 then
        is_default = string.unpack("I1", tlv_value)
      end

      if is_default == 1 then
        info.config_status = "default/unmanaged"
      elseif is_default == 0 then
        info.config_status = "managed/adopted"
      end

    else

    -- Other known or observed values
    -- Some have been seen in code but not observed to test while others have
    -- been observed but we don't know how to decode them.

    -- 0x06 - username
    -- 0x07 - salt
    -- 0x08 - random challenge
    -- 0x09 - challenge
    -- 0x0e - WMODE - state of config? length 1 value 03 value 02
    -- 0x10 - length 2 value e4b2 value e8a5 e815
    -- 0x12 - SEQ - lenth 4
    -- 0x13 - Source Mac, unused?
    -- 0x18 - length 4 and 4 nulls, or length 1 and 0xff
    -- 0xff - length 2 value e835

      stdnse.debug1("Unknown tag: %s - length: %d value: %s",
                    stdnse.tohex(tlv_type), tlv_len,
                    stdnse.tohex(tlv_value))
    end

    pos = pos + tlv_len
  end

  if next(mac_ip_table) ~= nil then
    info.interface_to_ip = {}
    for k, _ in pairs(mac_ip_table) do
      info.interface_to_ip[k] = tableaux.keys(mac_ip_table[k])
   end
  end

  if next(unique_macs) ~= nil then
    info.mac_addresses = tableaux.keys(unique_macs)
  end

  return info
end

---
-- Send probe and handle housekeeping
--
-- @param host A host table for the target host
-- @param port A port table for the target port
-- @return (status, result) If status is true, result the target's response to
--   a probe. If status is false, result is an error message.
local function send_probe(host, port, probe)

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local try = nmap.new_try(function() socket:close() end)

  try( socket:connect(host, port) )
  try( socket:send(probe) )

  local stat, resp = socket:receive_bytes(4)
  socket:close()

  return stat, resp
end

function action(host, port)

  local status, response = send_probe(host, port, PROBE_V1)

  if not status then
    status, response = send_probe(host, port, PROBE_V2)

    if not status then
      return nil
    end
  end

  nmap.set_port_state(host, port, "open")

  local result = parse_discovery_response(response)

  if not result then
    return nil
  end

  port.version.name = "ubiquiti-discovery"
  port.version.product = "Ubiquiti Discovery Service"

  local extrainfo = result.protocol .. " protocol"
  if result.product then
    extrainfo = extrainfo .. ", " .. result.product
  elseif result.model then
    extrainfo = extrainfo .. ", " .. result.model
  end

  if result.version then
    port.version.extrainfo = extrainfo .. " software ver. " .. result.version
  end

  port.version.ostype = "Linux"
  nmap.set_port_version(host, port, "hardmatched")

  return result
end
