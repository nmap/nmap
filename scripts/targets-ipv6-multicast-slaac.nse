description = [[
Does IPv6 host discovery by triggering stateless address auto-configuration
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
* http://dev.metasploit.com/redmine/projects/framework/repository/changes/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement.rb
]]

---
-- @usage
-- ./nmap -6 --script=slaac_host_discovery.nse --script-args 'newtargets,interface=eth0' -sP
-- @args targets-ipv6-multicast-slaac.interface  The interface to use for host discovery.

author = "David and Weilin"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery","broadcast"}

require 'nmap'
require 'target'
require 'packet'
require "os"
require "math"

prerule = function()
	return nmap.is_privileged()
end

catch = function()
	dnet:ethernet_close()
	pcap:pcap_close()
end
try = nmap.new_try(catch)

local function get_identifier(ip6_addr)
	return string.sub(ip6_addr, 9, 16)
end

--- Get a Unique-local Address with random global ID.
-- @param local_scope The scope of the address, local or reserved.
-- @return A 16-byte string of IPv6 address, and the length of the prefix.
local function get_radom_ula_prefix(local_scope)
	local ula_prefix
	math.randomseed(os.time())
	local global_id = string.char(math.random(256)-1,math.random(256)-1,math.random(256)-1,math.random(256)-1,math.random(256)-1)

	if local_scope then
		ula_prefix = packet.ip6tobin("fd00::")
	else
		ula_prefix = packet.ip6tobin("fc00::")
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
		string.char(0,0,0,0) .. --unknown
		prefix
	local icmpv6_prefix_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_PREFIX_INFORMATION,prefix_option_msg)
	local icmpv6_src_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_SOURCE_LINKADDR,mac_src)
	local icmpv6_payload = ra_msg .. icmpv6_prefix_option .. icmpv6_src_link_option
	return icmpv6_payload
end

action = function()
	local if_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()
	if not if_name then
		return "Error: need an interface name.\n"
			.. "Use -e <iface> or --script-args " .. SCRIPT_NAME .. ".interface=<iface>."
	end

	local if_nfo, err = nmap.get_interface_info(if_name)
	if not if_nfo then
		stdnse.print_debug(err)
		return false
	end
	if if_nfo.link ~= "ethernet" then
		stdnse.print_debug("Not a Ethernet link.")
		return false
	end
	local src_mac = if_nfo.mac
	local src_ip6 = packet.ip6tobin(if_nfo.address)
	local dst_mac = packet.mactobin("33:33:00:00:00:01")
	local dst_ip6 = packet.ip6tobin("ff02::1")
	local id_set = {}

----------------------------------------------------------------------------
--SLAAC-based host discovery probe

	local dnet = nmap.new_dnet()
	local pcap = nmap.new_socket()

	try(dnet:ethernet_open(if_name))
	pcap:pcap_open(if_name, 128, true, "src ::0/128 and dst net ff02::1:0:0/96 and icmp6 and ip6[6:1] = 58 and ip6[40:1] = 135")

	local actual_prefix = string.sub(src_ip6,1,8)
	local ula_prefix, prefix_len = get_radom_ula_prefix()

	-- preferred_lifetime <= valid_lifetime.
	-- Nmap will get the whole IPv6 addresses of each host if the two parameters are both longer than 5 seconds.
	-- Sometimes it makes sense to regard the several addresses of a host as different hosts, as the host's administrator may apply different firewall configurations on them.
	local valid_lifetime = 6
	local preferred_lifetime = 6

	local probe = packet.Frame:new()

	probe.ip6_src = packet.mac_to_lladdr(src_mac)
	probe.ip6_dst = dst_ip6
	probe.mac_src = src_mac
	probe.mac_dst = packet.mactobin("33:33:00:00:00:01")

	local icmpv6_payload = build_router_advert(src_mac,ula_prefix,prefix_len,valid_lifetime,preferred_lifetime)
	probe:build_icmpv6_header(packet.ND_ROUTER_ADVERT, 0, icmpv6_payload)
	probe:build_ipv6_packet()
	probe:build_ether_frame()

	try(dnet:ethernet_send(probe.frame_buf))

	local expected_mac_dst_prefix = packet.mactobin("33:33:ff:00:00:00")
	local expected_ip6_src = packet.ip6tobin("::")
	local expected_ip6_dst_prefix = packet.ip6tobin("ff02::1:0:0")

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
			if string.sub(reply.mac_dst, 1, 3) == string.sub(expected_mac_dst_prefix, 1, 3) then
				reply = packet.Packet:new(layer3)
				if reply.ip6_src == expected_ip6_src and
					string.sub(expected_ip6_dst_prefix,1,12) == string.sub(reply.ip6_dst,1,12) then
					local ula_target_addr_str = packet.toipv6(reply.ns_target)
					local identifier = get_identifier(reply.ns_target)
					found_targets = found_targets + 1
					--Filter out the reduplicative identifiers.
					--A host will send several NS packets with the same interface identifier if it receives several RA packets with different prefix during the discovery phase.
					if not id_set[identifier] then
						id_set[identifier] = true
						local actual_addr_str = packet.toipv6(actual_prefix .. identifier)
						target.add(actual_addr_str)
					end
				end
			end
		end
	until pcap_timeout_count >= 2 or cur_time - start_time >= nse_timeout

	dnet:ethernet_close()
	pcap:pcap_close()
	return true
end
