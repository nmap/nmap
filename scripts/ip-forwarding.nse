local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

description = [[
Detects whether the remote device has ip forwarding or "Internet connection
sharing" enabled, by sending an ICMP echo request to a given target using
the scanned host as default gateway.

The given target can be a routed or a LAN host and needs to be able to respond
to ICMP requests (ping) in order for the test to be successful. In addition,
if the given target is a routed host, the scanned host needs to have the proper
routing to reach it.

In order to use the scanned host as default gateway Nmap needs to discover
the MAC address. This requires Nmap to be run in privileged mode and the host
to be on the LAN.
]]

---
-- @usage
-- sudo nmap -sn <target> --script ip-forwarding --script-args='target=www.example.com'
--
-- @output
-- | ip-forwarding:
-- |_  The host has ip forwarding enabled, tried ping against (www.example.com)
--
-- @args ip-forwarding.target a LAN or routed target responding to ICMP echo
--        requests (ping).
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")

hostrule = function(host)
  if ( not(host.mac_addr) ) then
    stdnse.debug1("Failed to determine hosts remote MAC address" )
  end
  return (arg_target ~= nil and host.mac_addr ~= nil)
end


icmpEchoRequest = function(ifname, host, addr)
  local iface = nmap.get_interface_info(ifname)
  local dnet, pcap = nmap.new_dnet(), nmap.new_socket()

  pcap:set_timeout(5000)
  pcap:pcap_open(iface.device, 128, false, ("ether src %s and icmp and ( icmp[0] = 0 or icmp[0] = 5 ) and dst %s"):format(stdnse.format_mac(host.mac_addr), iface.address))
  dnet:ethernet_open(iface.device)

  local probe = packet.Frame:new()
  probe.mac_src = iface.mac
  probe.mac_dst = host.mac_addr
  probe.ip_bin_src = ipOps.ip_to_str(iface.address)
  probe.ip_bin_dst = ipOps.ip_to_str(addr)
  probe.echo_id = 0x1234
  probe.echo_seq = 6
  probe.echo_data = "Nmap host discovery."
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

  local target = ipOps.ip_to_bin(arg_target)
  if ( not(target) ) then
    local status
    status, target = dns.query(arg_target, { dtype='A' })
    if ( not(status) ) then
      return fail(("Failed to lookup hostname: %s"):format(arg_target))
    end
  else
    target = arg_target
  end

  if ( target == host.ip ) then
    return fail("Target can not be the same as the scanned host")
  end

  if (icmpEchoRequest(ifname, host, target)) then
    return ("\n  The host has ip forwarding enabled, tried ping against (%s)"):format(arg_target)
  end

end

