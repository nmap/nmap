local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

description = [[
Checks whether ipv4 forwarding is enabled on the targeted host. The targeted host needs to be on
the same network. The check is based on an ICMP echo request, that is send to the target with
a destination address of 8.8.8.8 and a time-to-live (TTL) of 1. The server's response depends on
it's forwarding settings:

1. If IPv4 forwarding is disabled, the server ignores the packet and causes a time out.
2. If IPv4 forwarding is enabled, the server either replies with an ICMP type 3 packet
   (destination unreachable) or an ICMP type 11 packet (time-to-live exceeded).

Depending on the response send by the server, we know whether forwarding is enabled or not.

This check is based on the original ip-forwarding check of nmap written by Patrik Karlsson.
]]

---
-- @usage
-- sudo nmap --script=ip-forwarding -sn <target>
--
-- @output
-- | ip-forwarding:
-- |_  The host has ip forwarding enabled!
--

author = "Tobias Neitzel (@qtc_de)"
license = "Same as Nmap. See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  if ( not(host.mac_addr) ) then
    stdnse.debug1("Failed to determine remote hosts MAC address" )
  end
  return (host.mac_addr ~= nil)
end


icmpEchoRequest = function(ifname, host)
  local iface = nmap.get_interface_info(ifname)
  local dnet, pcap = nmap.new_dnet(), nmap.new_socket()

  ident = math.random(256,65635)

  pcap:set_timeout(5000)
  pcap:pcap_open(iface.device, 128, false, ("icmp and ( icmp[0] = 3 or icmp[0] = 11 ) and icmp[32:2] = %d and dst %s"):format(ident, iface.address))

  dnet:ethernet_open(iface.device)

  local probe = packet.Frame:new()
  probe.mac_src = iface.mac
  probe.mac_dst = host.mac_addr
  probe.ip_bin_src = ipOps.ip_to_str(iface.address)
  probe.ip_bin_dst = ipOps.ip_to_str('8.8.8.8')
  probe.echo_id = ident
  probe.echo_seq = 6
  probe.ip_ttl = 1
  probe.echo_data = "Nmap ip-forwarding check."
  probe:build_icmp_echo_request()
  probe:build_icmp_header()
  probe:build_ip_packet()
  probe:build_ether_frame()

  dnet:ethernet_send(probe.frame_buf)
  local status = pcap:pcap_receive()
  dnet:ethernet_close()
  return status
end


local function fail(err) return stdnse.format_output(false, err) end


action = function(host)
  local ifname = nmap.get_interface() or host.interface
  if ( not(ifname) ) then
    return fail("Failed to determine the network interface name")
  end

  if (icmpEchoRequest(ifname, host)) then
    return ("\n  The host has ip forwarding enabled!")
  end
end
