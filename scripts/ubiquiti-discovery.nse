local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local stdnse = require "stdnse"
local string = require "string"
local ipOps = require "ipOps"

description = [[
Extracts information from Ubiquiti networking devices.

This script leverages Ubiquiti's Discovery Service which is enabled by default
on many products.
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
-- 10001/udp open  ubiquiti-discovery Ubiquiti Discovery Service (ER-X v1.10.7)
--
-- | ubiquiti-discovery:
-- |   uptime_seconds: 84592
-- |   uptime: 0 days 23:29:52
-- |   hostname: ubnt-router
-- |   product: ER-X
-- |   firmware: EdgeRouter.ER-e50.v1.10.7.5127989.181001.1227
-- |   version: v1.10.7
-- |   mac_ip:
-- |     80:2a:a8:df:a1:63: 192.168.0.1
-- |     80:2a:a8:df:a1:5e: 55.55.55.55
-- |   mac_addresses:
-- |     80:2a:a8:df:a1:63
-- |_    80:2a:a8:df:a1:5e
--
--@xmloutput
-- <elem key="uptime_seconds">84592</elem>
-- <elem key="uptime">0 days 23:33:00</elem>
-- <elem key="hostname">ubnt-router</elem>
-- <elem key="product">ER-X</elem>
-- <elem key="firmware">EdgeRouter.ER-e50.v1.10.7.5127989.181001.1227</elem>
-- <elem key="version">v1.10.7</elem>
-- <table key="mac_ip">
--   <elem key="80:2a:a8:df:a1:63">192.168.0.1</elem>
--   <elem key="80:2a:a8:df:a1:5e">55.55.55.55</elem>
-- </table>
-- <table key="mac_addresses">
--   <elem>80:2a:a8:df:a1:63</elem>
--   <elem>80:2a:a8:df:a1:5e</elem>
-- </table>


portrule = shortport.port_or_service(10001, "ubiquiti-discovery", "udp", {"open", "open|filtered"})

PROBE_V1 = string.pack("BB I2",
  0x01, 0x00, -- version, command
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
  local uptime_num = tonumber(uptime)
  if not uptime_num then
    return nil
  end

  local d = math.floor(uptime_num / 86400)
  local h = math.floor(uptime_num /  3600 % 24)
  local m = math.floor(uptime_num /    60 % 60)
  local s = math.floor(uptime_num % 60)

  return string.format("%d days %02d:%02d:%02d", d, h, m, s)
end

---
-- Parses the full payload of a discovery response
--
-- @param payload containing response
-- @return output_table containing results or nil
local function parse_v1_discovery_response(response)

  local info = stdnse.output_table()
  local unique_macs = {}
  local mac_ip_table = {}

  if #response < 4 then
    return nil
  end

  -- Check for v1 protocol header
  if not ( response:byte(1) == 0x01 and response:byte(2) == 0x00 ) then
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
      mac_ip_table[mac] = ip

    elseif tlv_type == 0x03 then
      info.firmware = tlv_value

      local human_version = tlv_value:match("%.(v%d+%.%d+%.%d+)")
      if human_version then
        info.version = human_version
      end

    elseif tlv_type == 0x0a then
      local uptime_raw = string.unpack(">I4", tlv_value)
      info.uptime_seconds = uptime_raw
      info.uptime = uptime_str(uptime_raw)

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

    elseif tlv_type == 0x14 then
      info.model = tlv_value

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
    -- 0x18 - length 4 and 4 nulls, or length 1 and 0xff
    -- 0xff - length 2 value e835

      stdnse.debug1("Unknown tag: %s - length: %d value: %s",
                    stdnse.tohex(tlv_type), tlv_len,
                    stdnse.tohex(tlv_value))
    end

    pos = pos + tlv_len
  end

  if mac_ip_table then
    info.mac_ip = mac_ip_table
  end

  if unique_macs then
    info.mac_addresses = {}
    for k, _ in pairs(unique_macs) do
      table.insert(info.mac_addresses, k)
    end
  end

  return info
end

function action(host, port)

  local socket = nmap.new_socket()
  socket:connect(host, port)
  socket:send(PROBE_V1)

  local status, response = socket:receive()
  if not status then
    return nil
  end

  nmap.set_port_state(host, port, "open")

  local result = parse_v1_discovery_response(response)
  if not result then
    return nil
  end

  port.version.name = "ubiquiti-discovery"
  port.version.product = "Ubiquiti Discovery Service"
  if result.version then
    port.version.extrainfo = result.product .. " " .. result.version
  else
    port.version.extrainfo = result.product
  end
  port.version.ostype = "Linux"
  table.insert(port.version.cpe, "cpe:/h:ubnt")
  table.insert(port.version.cpe, "cpe:/a:ubnt")
  nmap.set_port_version(host, port, "hardmatched")

  return result
end
