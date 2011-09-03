description = [[
Multicast invalid packet host discovery.

This script works by sending an ICMPv6 packet with an invalid extension header
to the all-nodes link-local multicast address, <code>ff02::1</code>. Some hosts
will respond to this probe with an ICMPv6 Parameter Problem packet. This script
can discover hosts reachable on an interface without needing to individually
ping each address.
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

local function get_identifier(ip6_addr)
	return string.sub(ip6_addr, 9, 16)
end

--- Build an IPv6 invalid extension header.
-- @param nxt_hdr integer that stands for next header's type
local function build_invalid_extension_header(nxt_hdr)
	-- RFC 2640, section 4.2 defines the TLV format of options headers.
	-- It is important that the first byte have 10 in the most significant
	-- bits; that instructs the receiver to send a Parameter Problem.
	-- Option type 0x80 is unallocated; see
	-- http://www.iana.org/assignments/ipv6-parameters/.
	local ex_invalid_opt = string.char(0x80,0x01,0x00,0x00,0x00,0x00)
	local ext_header =
		string.char(nxt_hdr) .. --next header
		string.char(0) .. -- length 8
		ex_invalid_opt
	return ext_header
end

action = function()
	local if_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()
	local if_nfo = nmap.get_interface_info(if_name)
	if not if_nfo then
		stdnse.print_debug("Invalid interface: %s", if_name)
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

	-- In addition to setting an invalid option in
	-- build_invalid_extension_header, we set an unknown ICMPv6 type of
	-- 254. (See http://www.iana.org/assignments/icmpv6-parameters for
	-- allocations.) Mac OS X 10.6 appears to send a Parameter Problem
	-- response only if both of these conditions are met. In this we differ
	-- from the alive6 tool, which sends a proper echo request.
	probe.icmpv6_type = 254
	probe.icmpv6_code = 0
	-- Add a non-empty payload too.
	probe.icmpv6_payload = string.char(0x00, 0x00, 0x00, 0x00)
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

	dnet:ethernet_close()
	pcap:pcap_close()

	return true
end
