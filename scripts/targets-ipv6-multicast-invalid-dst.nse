description = [[
Multicast invalid destination options ping.
Do a very fast host discovery on link-local IPv6 network.
]]

---
-- @usage
-- ./nmap -6 --script=targets-ipv6-multicast-invalid-dst.nse --script-args 'newtargets,interface=eth0' -sP
-- @args newtargets  If true, add discovered targets to the scan queue.
-- @args targets-ipv6-multicast-invalid-dst.interface  The interface to use for host discovery.

author = "David and Weilin"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery"}

require 'nmap'
require 'target'
require 'packet'
local bit = require 'bit'

prerule = function()
	return nmap.is_privileged() and
		(stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface())
end

catch = function()
	dnet:ethernet_close()
	pcap:pcap_close()
end
try = nmap.new_try(catch)

local function get_ipv6_interface_info_by_name(if_name)
	local ifaces = nmap.list_interfaces()
	local iface
	local if_nfo
	for _,iface in pairs(ifaces) do
		if if_name == iface.device and (#iface.address>15 or string.find(iface.address, "::")) then
			if_nfo = iface
			return if_nfo
		end
	end
	return nil
end

local function get_identifier(ip6_addr)
	return string.sub(ip6_addr, 9, 16)
end

--- Build an IPv6 invalid extension header.
-- @param nxt_hdr integer that stands for next header's type
local function build_invalid_extension_header(nxt_hdr)
	local ex_invalid_opt = string.char(0x80,0x01,0xfe,0x18,0xfe,0x18,0xfe,0x18,0x0,0x0,0x0,0x0,0x0,0x0)
	local ext_header =
		string.char(nxt_hdr) .. --next header
		string.char(#ex_invalid_opt/16) .. --length (16bytes)
		ex_invalid_opt
	return ext_header
end

action = function()
	local if_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()
	local if_nfo = get_ipv6_interface_info_by_name(if_name)
	if not if_nfo then
		stdnse.print_debug("Invalid interface: " .. if_name)
		return false
	end
	local src_mac = if_nfo.mac
	local src_ip6 = packet.ip6tobin(if_nfo.address)
	local dst_mac = packet.mactobin("33:33:00:00:00:01")
	local dst_ip6 = packet.ip6tobin("ff02::1")
	local id_set = {}

----------------------------------------------------------------------------
--Multicast invalid destination exheader probe

	local dnet = nmap.new_dnet()
	local pcap = nmap.new_socket()

	try(dnet:ethernet_open(if_name))
	pcap:pcap_open(if_name, 128, false, "icmp6 and ip6[6:1] = 58 and ip6[40:1] = 4")

	local probe = packet.Frame:new()
	probe.mac_src = src_mac
	probe.mac_dst = dst_mac
	probe.ip6_src = src_ip6
	probe.ip6_dst = dst_ip6

	probe.echo_id = 5
	probe.echo_seq = 6
	probe.echo_data = "Nmap host discovery."
	probe:build_icmpv6_echo_request()
	probe:build_icmpv6_header()

	probe.exheader = build_invalid_extension_header(packet.IPPROTO_ICMPV6)
	probe.ip6_nxt_hdr = packet.IPPROTO_DSTOPTS

	probe:build_ipv6_packet()
	probe:build_ether_frame()

	try(dnet:ethernet_send(probe.frame_buf))

	pcap:set_timeout(1000)
	local pcap_timeout_count = 0
	local nse_timeout = 5
	local start_time = nmap:clock()
	local cur_time = nmap:clock()

	local found_targets = 0

	repeat
		local status, length, layer2, layer3 = pcap:pcap_receive()
		cur_time = nmap:clock()
		if not status then
			pcap_timeout_count = pcap_timeout_count + 1
		else
			local reply = packet.Frame:new(layer2)
			if reply.mac_dst == src_mac then
				reply = packet.Packet:new(layer3)
				local target_addr = reply.ip6_src
				found_targets = found_targets + 1
				local identifier = get_identifier(reply.ip6_src)
				if not id_set[identifier] then
					id_set[identifier] = true
					local target_str = packet.toipv6(target_addr)
					target.add(target_str)
				end
			end
		end
	until pcap_timeout_count >= 2 or cur_time - start_time >= nse_timeout

	stdnse.print_debug(0, "[Invalid DSTOPTS] Found %d targets.", found_targets)

	dnet:ethernet_close()
	pcap:pcap_close()

	return true
end
