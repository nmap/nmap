local coroutine = require "coroutine"
local ipOps = require "ipOps"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local target = require "target"

description = [[
Sends an ICMPv6 packet with an invalid extension header to the
all-nodes link-local multicast address (<code>ff02::1</code>) to
discover (some) available hosts on the LAN. This works because some
hosts will respond to this probe with an ICMPv6 Parameter Problem
packet.
]]

---
-- @usage
-- ./nmap -6 --script=targets-ipv6-multicast-invalid-dst.nse --script-args 'newtargets,interface=eth0' -sP
-- @output
-- Pre-scan script results:
-- | targets-ipv6-multicast-invalid-dst:
-- |   IP: 2001:0db8:0000:0000:0000:0000:0000:0001  MAC: 11:22:33:44:55:66  IFACE: eth0
-- |_  Use --script-args=newtargets to add the results as targets
-- @args newtargets  If true, add discovered targets to the scan queue.
-- @args targets-ipv6-multicast-invalid-dst.interface  The interface to use for host discovery.

author = "David Fifield, Xu Weilin"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery","broadcast"}


prerule = function()
  return nmap.is_privileged()
end

--- Build an IPv6 invalid extension header.
-- @param nxt_hdr integer that stands for next header's type
local function build_invalid_extension_header(nxt_hdr)
  -- RFC 2640, section 4.2 defines the TLV format of options headers.
  -- It is important that the first byte have 10 in the most significant
  -- bits; that instructs the receiver to send a Parameter Problem.
  -- Option type 0x80 is unallocated; see
  -- http://www.iana.org/assignments/ipv6-parameters/.
  return string.char(nxt_hdr, 0) .. --next header, length 8
  "\x80\x01\x00\x00\x00\x00"
end

local function get_interfaces()
  local interface_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
    or nmap.get_interface()

  -- interfaces list (decide which interfaces to broadcast on)
  local interfaces = {}
  if interface_name then
    -- single interface defined
    local if_table = nmap.get_interface_info(interface_name)
    if if_table and ipOps.ip_to_str(if_table.address) and if_table.link == "ethernet" then
      interfaces[#interfaces + 1] = if_table
    else
      stdnse.debug1("Interface not supported or not properly configured.")
    end
  else
    for _, if_table in ipairs(nmap.list_interfaces()) do
      if ipOps.ip_to_str(if_table.address) and if_table.link == "ethernet" then
        table.insert(interfaces, if_table)
      end
    end
  end

  return interfaces
end

local function single_interface_broadcast(if_nfo, results)
  stdnse.debug1("Starting " .. SCRIPT_NAME .. " on " .. if_nfo.device)

  local condvar = nmap.condvar(results)
  local src_mac = if_nfo.mac
  local src_ip6 = ipOps.ip_to_str(if_nfo.address)
  local dst_mac = packet.mactobin("33:33:00:00:00:01")
  local dst_ip6 = ipOps.ip_to_str("ff02::1")

  ----------------------------------------------------------------------------
  --Multicast invalid destination exheader probe

  local dnet = nmap.new_dnet()
  local pcap = nmap.new_socket()

  local function catch ()
    dnet:ethernet_close()
    pcap:pcap_close()
  end
  local try = nmap.new_try(catch)

  try(dnet:ethernet_open(if_nfo.device))
  pcap:pcap_open(if_nfo.device, 128, false, "icmp6 and ip6[6:1] = 58 and ip6[40:1] = 4")

  local probe = packet.Frame:new()
  probe.mac_src = src_mac
  probe.mac_dst = dst_mac
  probe.ip_bin_src = src_ip6
  probe.ip_bin_dst = dst_ip6

  -- In addition to setting an invalid option in
  -- build_invalid_extension_header, we set an unknown ICMPv6 type of
  -- 254. (See http://www.iana.org/assignments/icmpv6-parameters for
  -- allocations.) Mac OS X 10.6 appears to send a Parameter Problem
  -- response only if both of these conditions are met. In this we differ
  -- from the alive6 tool, which sends a proper echo request.
  probe.icmpv6_type = 254
  probe.icmpv6_code = 0
  -- Add a non-empty payload too.
  probe.icmpv6_payload = "\x00\x00\x00\x00"
  probe:build_icmpv6_header()

  probe.exheader = build_invalid_extension_header(packet.IPPROTO_ICMPV6)
  probe.ip6_nhdr = packet.IPPROTO_DSTOPTS

  probe:build_ipv6_packet()
  probe:build_ether_frame()

  try(dnet:ethernet_send(probe.frame_buf))

  pcap:set_timeout(1000)
  local pcap_timeout_count = 0
  local nse_timeout = 5
  local start_time = nmap:clock()
  local cur_time = nmap:clock()

  local addrs = {}

  repeat
    local status, length, layer2, layer3 = pcap:pcap_receive()
    cur_time = nmap:clock()
    if not status then
      pcap_timeout_count = pcap_timeout_count + 1
    else
      local l2reply = packet.Frame:new(layer2)
      if l2reply.mac_dst == src_mac then
        local reply = packet.Packet:new(layer3)
        local target_str = reply.ip_src
        if not results[target_str] then
          if target.ALLOW_NEW_TARGETS then
            target.add(target_str)
          end
          results[#results + 1] = { address = target_str, mac = stdnse.format_mac(l2reply.mac_src), iface = if_nfo.device }
          results[target_str] = true
        end
      end
    end
  until pcap_timeout_count >= 2 or cur_time - start_time >= nse_timeout

  dnet:ethernet_close()
  pcap:pcap_close()

  condvar("signal")
end

local function format_output(results)
  local output = tab.new()

  for _, record in ipairs(results) do
    tab.addrow(output, "IP: " .. record.address, "MAC: " .. record.mac, "IFACE: " .. record.iface)
  end
  if #results > 0 then
    output = { tab.dump(output) }
    if not target.ALLOW_NEW_TARGETS then
      output[#output + 1] = "Use --script-args=newtargets to add the results as targets"
    end
    return stdnse.format_output(true, output)
  end
end

action = function()
  local threads = {}
  local results = {}
  local condvar = nmap.condvar(results)

  for _, if_nfo in ipairs(get_interfaces()) do
    -- create a thread for each interface
    local co = stdnse.new_thread(single_interface_broadcast, if_nfo, results)
    threads[co] = true
  end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  return format_output(results)
end
