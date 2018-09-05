---
-- Utility functions for sending MLD requests and parsing reports.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local nmap = require "nmap"
local ipOps = require "ipOps"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("multicast", stdnse.seeall)

---
-- Performs an MLD general query on the selected interface and caches the results such that
-- subsequent calls to this function do not generate additional traffic.
--
-- @param if_nfo A table containing information about the interface to send the request on.
-- Can be one of those returned by nmap.list_interfaces().
-- @param arg_timeout The amount of time to wait for reports.
--
-- @return A list of tables, each table containing three items, namely device, layer 2 reply and layer 3 reply.
--
mld_query = function( if_nfo, arg_timeout )
  -- check if the interface name is valid or if nmap can find one
  if if_nfo == nil then
    return nil
  end

  -- we need some ID for this interface & address combination to use as the
  -- registry key and the object to lock the mutex on
  local reg_entry = "mld_reports_" .. if_nfo.device .. "_" .. if_nfo.address
  local mutex = nmap.mutex( reg_entry )
  mutex('lock')

  -- first check if nmap.registry contains reports for this interface from a previous call of this function
  if nmap.registry[reg_entry] ~= nil then
    mutex('done')
    return nmap.registry[reg_entry]
  end

  if not ipOps.ip_in_range(if_nfo.address, "fe80::/10")  -- link local address
    or if_nfo.link ~= "ethernet" then                 -- not the loopback interface
    mutex('done')
    return nil
  end

  -- create the query packet
  local src_mac = if_nfo.mac
  local src_ip6 = ipOps.ip_to_str(if_nfo.address)
  local dst_mac = packet.mactobin("33:33:00:00:00:01")
  local dst_ip6 = ipOps.ip_to_str("ff02::1")
  local general_qry = ipOps.ip_to_str("::")

  local dnet = nmap.new_dnet()
  local pcap = nmap.new_socket()

  dnet:ethernet_open(if_nfo.device)
  pcap:pcap_open(if_nfo.device, 1500, false, "ip6[40:1] == 58")

  local probe = packet.Frame:new()
  probe.mac_src = src_mac
  probe.mac_dst = dst_mac
  probe.ip_bin_src = src_ip6
  probe.ip_bin_dst = dst_ip6

  probe.ip6_tc = 0
  probe.ip6_fl = 0
  probe.ip6_hlimit = 1

  probe.icmpv6_type = packet.MLD_LISTENER_QUERY
  probe.icmpv6_code = 0

  -- Add a non-empty payload too.
  probe.icmpv6_payload = (
    "\x00\x01" ..              -- maximum response delay 1 millisecond (if 0, virtualbox TCP/IP stack crashes)
    "\x00\x00" ..              -- reserved
    ipOps.ip_to_str("::")   -- empty address - general MLD query
  )
  probe:build_icmpv6_header()
  probe.exheader = string.pack(">BBBB I2 BB",
    packet.IPPROTO_ICMPV6,  -- next header
    0x00, -- length not including first 8 octets
    0x05, -- type is router alert
    0x02, -- length 2 bytes
    0x00, -- router alert MLD
    0x01, -- padding type PadN
    0x00  -- padding length 0
  )
  probe.ip6_nhdr = packet.IPPROTO_HOPOPTS
  probe:build_ipv6_packet()
  probe:build_ether_frame()

  -- send the query packet
  dnet:ethernet_send(probe.frame_buf)

  -- wait for responses to the query packet
  pcap:set_timeout(1000)
  local pcap_timeout_count = 0
  local nse_timeout = arg_timeout or 10
  local start_time = nmap:clock()
  local addrs = {}
  nmap.registry[reg_entry] = {}

  repeat
    local status, length, layer2, layer3 = pcap:pcap_receive()
    local cur_time = nmap:clock()
    if status then
      local l2reply = packet.Frame:new(layer2)
      local l3reply = packet.Packet:new(layer3, length, true)
      local target_ip = l3reply.ip_src
      if l3reply.ip6_nhdr == packet.MLD_LISTENER_REPORT or l3reply.ip6_nhdr == packet.MLDV2_LISTENER_REPORT then
        table.insert(
          nmap.registry[reg_entry],
          { if_nfo.device, l2reply, l3reply }
        )
      end
    end
  until ( cur_time - start_time >= nse_timeout )

  -- clean up
  dnet:ethernet_close()
  pcap:pcap_close()

  mutex('done')
  return nmap.registry[reg_entry]
end

---
-- Extracts IP addresses from MLD reports captured by the mld_query function.
--
-- @param reports The output of the mld_query function.
--
-- @return A list of tables, each table containing three items, namely device, mac and a list of addresses.
--
mld_report_addresses = function(reports)
  local rep_addresses = {}
  for _, report in pairs(reports) do
    local device = report[1]
    local l2reply = report[2]
    local l3reply = report[3]

    local target_ip = l3reply.ip_src
    if l3reply.ip6_nhdr == packet.MLD_LISTENER_REPORT or l3reply.ip6_nhdr == packet.MLDV2_LISTENER_REPORT then

      -- if this is the first reply from the target, make an entry for it
      if not rep_addresses[target_ip] then
        rep_addresses[target_ip] = stdnse.output_table()
      end
      local rep = rep_addresses[target_ip]
      rep.device = device
      rep.mac = stdnse.format_mac(l2reply.mac_src)
      rep.multicast_ips = rep.multicast_ips or {}

      -- depending on the MLD version of the report, add appropriate IP addresses
      if l3reply.ip6_nhdr == packet.MLD_LISTENER_REPORT then
        local multicast_ip = ipOps.str_to_ip( l3reply:raw(0x38, 16) ) -- IP starts at byte 0x38 and is 16 bytes long
        table.insert(rep.multicast_ips, multicast_ip)
      elseif l3reply.ip6_nhdr == packet.MLDV2_LISTENER_REPORT then
        local no_records = l3reply:u16(0x36)
        local record_offset = 0
        local records_start = 0x38
        for i = 1, no_records do
          -- for the format description, see RFC3810 (ch. 5.2)
          local aux_data_len = l3reply:u8(records_start + record_offset + 1)
          local no_sources = l3reply:u16(records_start + record_offset + 2)
          local multicast_ip = ipOps.str_to_ip(l3reply:raw(records_start + record_offset + 4, 16))
          table.insert(rep.multicast_ips, multicast_ip)
          record_offset = record_offset + 4 + 16 + no_sources * 16 + aux_data_len * 4
        end
      end

    end
  end
  return rep_addresses
end

return _ENV
