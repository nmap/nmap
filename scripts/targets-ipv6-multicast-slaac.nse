local coroutine = require "coroutine"
local ipOps = require "ipOps"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local target = require "target"
local rand = require "rand"

description = [[
Performs IPv6 host discovery by triggering stateless address auto-configuration
(SLAAC).

This script works by sending an ICMPv6 Router Advertisement with a random
address prefix, which causes hosts to begin SLAAC and send a solicitation for
their newly configured address, as part of duplicate address detection. The
script then guesses the remote addresses by combining the link-local prefix of
the interface with the interface identifier in each of the received
solicitations. This should be followed up with ordinary ND host discovery to
verify that the guessed addresses are correct.

The router advertisement has a router lifetime of zero and a short prefix
lifetime (a few seconds)

See also:
* RFC 4862, IPv6 Stateless Address Autoconfiguration, especially section 5.5.3.
* https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement.rb
]]

---
-- @usage
-- nmap -6 --script targets-ipv6-multicast-slaac --script-args 'newtargets,interface=eth0' -sP
-- @output
-- Pre-scan script results:
-- | targets-ipv6-multicast-slaac:
-- |   IP: fe80:0000:0000:0000:1322:33ff:fe44:5566  MAC: 11:22:33:44:55:66  IFACE: eth0
-- |_  Use --script-args=newtargets to add the results as targets
-- @args targets-ipv6-multicast-slaac.interface  The interface to use for host discovery.

author = {"David Fifield", "Xu Weilin"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery","broadcast"}


prerule = function()
  return nmap.is_privileged()
end

local function get_identifier(ip6_addr)
  return string.sub(ip6_addr, 9, 16)
end

--- Get a Unique-local Address with random global ID.
-- @param local_scope The scope of the address, local or reserved.
-- @return A 16-byte string of IPv6 address, and the length of the prefix.
local function get_random_ula_prefix(local_scope)
  local ula_prefix
  local global_id = rand.random_string(5)

  if local_scope then
    ula_prefix = ipOps.ip_to_str("fd00::")
  else
    ula_prefix = ipOps.ip_to_str("fc00::")
  end
  ula_prefix = string.sub(ula_prefix,1,1) .. global_id .. string.sub(ula_prefix,7,-1)
  return ula_prefix,64
end

--- Build an ICMPv6 payload of Router Advertisement.
-- @param mac_src six-byte string of the source MAC address.
-- @param prefix 16-byte string of IPv6 address.
-- @param prefix_len integer that represents the length of the prefix.
-- @param valid_time integer that represents the valid time of the prefix.
-- @param preferred_time integer that represents the preferred time of the prefix.
local function build_router_advert(mac_src,prefix,prefix_len,valid_time,preferred_time)
  local ra_msg = string.char(0x0, --cur hop limit
  0x08, --flags
  0x00,0x00, --router lifetime
  0x00,0x00,0x00,0x00, --reachable time
  0x00,0x00,0x00,0x00) --retrans timer
  local prefix_option_msg = string.char(prefix_len, 0xc0) .. --flags: Onlink, Auto
    packet.set_u32("....",0,valid_time) ..
    packet.set_u32("....",0,preferred_time) ..
    "\0\0\0\0" .. --unknown
    prefix
  local icmpv6_prefix_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_PREFIX_INFORMATION,prefix_option_msg)
  local icmpv6_src_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_SOURCE_LINKADDR,mac_src)
  local icmpv6_payload = ra_msg .. icmpv6_prefix_option .. icmpv6_src_link_option
  return icmpv6_payload
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
  --SLAAC-based host discovery probe

  local dnet = nmap.new_dnet()
  local pcap = nmap.new_socket()

  local function catch ()
    dnet:ethernet_close()
    pcap:pcap_close()
  end
  local try = nmap.new_try(catch)

  try(dnet:ethernet_open(if_nfo.device))
  pcap:pcap_open(if_nfo.device, 128, true, "src ::0/128 and dst net ff02::1:0:0/96 and icmp6 and ip6[6:1] = 58 and ip6[40:1] = 135")

  local actual_prefix = string.sub(src_ip6,1,8)
  local ula_prefix, prefix_len = get_random_ula_prefix()

  -- preferred_lifetime <= valid_lifetime.
  -- Nmap will get the whole IPv6 addresses of each host if the two parameters are both longer than 5 seconds.
  -- Sometimes it makes sense to regard the several addresses of a host as
  -- different hosts, as the host's administrator may apply different firewall
  -- configurations on them.
  local valid_lifetime = 6
  local preferred_lifetime = 6

  local probe = packet.Frame:new()

  probe.ip_bin_src = packet.mac_to_lladdr(src_mac)
  probe.ip_bin_dst = dst_ip6
  probe.mac_src = src_mac
  probe.mac_dst = packet.mactobin("33:33:00:00:00:01")

  local icmpv6_payload = build_router_advert(src_mac,ula_prefix,prefix_len,valid_lifetime,preferred_lifetime)
  probe:build_icmpv6_header(packet.ND_ROUTER_ADVERT, 0, icmpv6_payload)
  probe:build_ipv6_packet()
  probe:build_ether_frame()

  try(dnet:ethernet_send(probe.frame_buf))

  local expected_mac_dst_prefix = packet.mactobin("33:33:ff:00:00:00")
  local expected_ip6_src = ipOps.ip_to_str("::")
  local expected_ip6_dst_prefix = ipOps.ip_to_str("ff02::1:0:0")

  pcap:set_timeout(1000)
  local pcap_timeout_count = 0
  local nse_timeout = 5
  local start_time = nmap:clock()
  local cur_time = nmap:clock()

  repeat
    local status, length, layer2, layer3 = pcap:pcap_receive()
    cur_time = nmap:clock()
    if not status then
      pcap_timeout_count = pcap_timeout_count + 1
    else
      local l2reply = packet.Frame:new(layer2)
      if string.sub(l2reply.mac_dst, 1, 3) == string.sub(expected_mac_dst_prefix, 1, 3) then
        local reply = packet.Packet:new(layer3)
        if reply.ip_bin_src == expected_ip6_src and
          string.sub(expected_ip6_dst_prefix,1,12) == string.sub(reply.ip_bin_dst,1,12) then
          local ula_target_addr_str = ipOps.str_to_ip(reply.ns_target)
          local identifier = get_identifier(reply.ns_target)
          --Filter out the reduplicative identifiers.
          --A host will send several NS packets with the same interface
          --identifier if it receives several RA packets with different prefix
          --during the discovery phase.
          local actual_addr_str = ipOps.str_to_ip(actual_prefix .. identifier)
          if not results[actual_addr_str] then
            if target.ALLOW_NEW_TARGETS then
              target.add(actual_addr_str)
            end
            results[#results + 1] = { address = actual_addr_str, mac = stdnse.format_mac(l2reply.mac_src), iface = if_nfo.device }
            results[actual_addr_str] = true
          end
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
    if ipOps.ip_in_range(if_nfo.address, "fe80::/10") then
      local co = stdnse.new_thread(single_interface_broadcast, if_nfo, results)
      threads[co] = true
    end
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
