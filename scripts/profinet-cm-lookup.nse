local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"

description = [[
Sends a DCERPC EPM Lookup Request to PROFINET devices. the DCE/RPC Endpoint Mapper (EPM) targeting Profinet Devices.

Profinet Devices support the udp-based PNIO-CM protocol under port 34964.
PNIO-CM uses DCE/RPC as its underlying protocol.


Profinet Devices support a DCE/RPC UUID Entity under the UUID variant
'dea00001-6c97-11d1-8271-00a02442df7d'. This script sends the Lookup Request for this UUID.

References:
* https://rt-labs.com/docs/p-net/profinet_details.html#dce-rpc-uuid-entities
* https://wiki.wireshark.org/EPM
]]

---
-- @usage nmap -sU <target_ip> -p 34964 --script profinet-cm-lookup
---
-- @output
--PORT		STATE	SERVICE			REASON
--34964/udp open|filtered profinet-cm no-response
--| profinet-cm-lookup:
--|   ipAddress: 192.168.10.12
--|   annotationOffset: 0
--|   annotationLength: 64
--|_  annotation: S7-1500                   6ES7 672-5DC01-0YA0      0 V  2  1  7
-- @xmloutput
--<elem key="ipAddress">192.168.10.12</elem>
--<elem key="annotationOffset">0</elem>
--<elem key="annotationLength">64</elem>
--<elem key="annotation">S7-1500                   6ES7 672-5DC01-0YA0      0 V  2  1  7</elem>

categories = {"discovery", "intrusive"}
author = "DINA-community"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local EPM_UDP_PORT = 34964

local DCE_RPC_REQUEST = string.char(
  0x04,0x00,0x20,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x83,0xaf,0xe1,0x1f,0x5d,0xc9,0x11,
  0x91,0xa4,0x08,0x00,0x2b,0x14,0xa0,0xfa,0x01,0x00,0x00,0x00,0x01,0x00,0x01,0x00,
  0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,
  0x0c,0x00,0x00,0x00,0x02,0x00,0xff,0xff,0xff,0xff,0x4c,0x00,0x00,0x00,0x00,0x00)

local EPM_Lookup = string.char(
  0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0xa0,0xde,
  0x97,0x6c,0xd1,0x11,0x82,0x71,0x00,0xa0,0x24,0x42,0xdf,0x7d,0x01,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00)


-- The Rules
portrule = shortport.port_or_service(34964, "profinet-cm", "udp")
if not nmap.is_privileged() then
    stdnse.debug(1, "Nmap is NOT running as privileged.")
    portrule = nil
    prerule = function() return false end
end

-- The Action

---
-- Parses the EPM Lookup Response extracting the annotation field containing the
-- product name and the article number of the scanned PNIO Device
---
parse_response = function(host, port, layer3)
  -- print raw bytes of reponse
  stdnse.debug(2, "Raw hex: %s", stdnse.tohex(layer3))

  -- parse byte order/ endianness
  local order_tmp = string.unpack('B', layer3, 33)
  local order = order_tmp >> 4
  local format_prefix = order == 0 and ">" or "<"

  stdnse.debug(1, "little_endian: " .. tostring(order))

  -- parse annotationOffset
  local annotationOffset = string.unpack("I4", layer3, 165)
  stdnse.debug(1, "annotationOffset 0x%s", stdnse.tohex(annotationOffset))

  -- parse annotationLength
  local annotation_length_format = string.format("%si4", format_prefix)
  stdnse.debug(1, annotation_length_format)
  local annotationLength = string.unpack(annotation_length_format, layer3, 169)
  stdnse.debug(1, "annotationLength " .. annotationLength)

  -- parse annotation
  local annotation_format = string.format("c%d", annotationLength)
  local annotation = string.unpack(annotation_format, layer3, 173)
  stdnse.debug(1, "annotation:  " .. annotation)

  -- create table for output
  local output = stdnse.output_table()
  output["ipAddress"] = host.ip
  output["annotationOffset"] = annotationOffset
  output["annotationLength"] = annotationLength
  output["annotation"] = annotation

  return output
end

-- Sends the udp payload and parses the response
lookup_request = function(host, port, payload, timeout)
  local socket, try, catch

  -- create a new udp socket for sending the lookup request
  local socket = nmap.new_socket("udp")

  -- create a socket for receiving incoming data
  -- 'socket:receive()'' alone won't suffice as the UDP port of
  -- the scanned device can be selected arbitrarily
  local pcap = nmap.new_socket()

  -- set timeout
  socket:set_timeout(tonumber(timeout))

  catch = function()
    pcap:close()
    socket:close()
  end

  -- create new try
  try = nmap.new_try(catch)

  -- connect to port on host for sending payload
  try(socket:connect(host.ip, port["number"], "udp"))

  local status, lhost, lport, rhost, rport = socket:get_info()

  if status then
    -- configuration for pcap:pcap_receive()
    pcap:pcap_open(host.interface, 1500, false, "udp dst port " .. lport .. " and src host " .. host.ip)
    pcap:set_timeout(host.times.timeout * 1000)

    -- send lookup packet with PNIO Interface UUID
    try(socket:send(payload))

    -- receive response
    local status_rec, len, _, layer3 = pcap:pcap_receive()

    -- when successful, set port state to "open" and parse response
    if status_rec and len > 200 then
      nmap.set_port_state(host, port, "open")
      return parse_response(host, port, layer3)
    end
  end

  -- close sockets
  pcap:close()
  socket:close()

end

-- MAIN
action = function(host, port)
  local payload = DCE_RPC_REQUEST .. EPM_Lookup
  local timeout = stdnse.get_timeout(host)
  return lookup_request(host, port, payload, timeout)
end
