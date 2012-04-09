description = [[
Sends an MLD query with maximum response delay 0 to the
to discover available hosts on the LAN. This works because 
hosts will respond to this probe with an MLD report packet and 
as maximum response delay is 0 nobody gets time to wait for others`
report even in the same multicast group.
]]

---
-- @usage
-- nmap -6 --script=targets-ipv6-multicast-mld.nse --script-args 'newtargets,interface=eth0' -sP
--
-- Pre-scan script results:
-- | targets-ipv6-multicast-mld: 
-- |   IP: fe80::5a55:abcd:ef01:2345  MAC: 58:55:ab:cd:ef:01  IFACE: en0
-- |   IP: fe80::9284:0123:4567:89ab  MAC: 90:84:01:23:45:67  IFACE: en0
-- |   
-- |_  Use --script-args=newtargets to add the results as targets
--
-- @args targets-ipv6-multicast-mld.timeout timeout in seconds to wait for 
--       responses (default: 10)
--

author = "niteesh"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","broadcast"}

local nmap		= require 'nmap'
local tab 		= require 'tab'
local target 	= require 'target'
local packet	= require 'packet'
local bit		= require 'bit'
local bin		= require 'bin'

local arg_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout'))

prerule = function()
	if ( not(nmap.is_privileged()) ) then
		stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
		return false
	end
	return true
end


local function get_interfaces()
	local interface_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
		or nmap.get_interface()

	-- interfaces list (decide which interfaces to broadcast on)
	local interfaces = {}
	if interface_name then
		-- single interface defined
		local if_table = nmap.get_interface_info(interface_name)
		if if_table and packet.ip6tobin(if_table.address) and if_table.link == "ethernet" then
			interfaces[#interfaces + 1] = if_table
		else
			stdnse.print_debug("Interface not supported or not properly configured.")
		end
	else
		for _, if_table in ipairs(nmap.list_interfaces()) do
			if packet.ip6tobin(if_table.address) and if_table.link == "ethernet" then
				table.insert(interfaces, if_table)
			end
		end
	end

	return interfaces
end

local function single_interface_broadcast(if_nfo, results)
	stdnse.print_debug(2, "Starting " .. SCRIPT_NAME .. " on " .. if_nfo.device)
	local condvar = nmap.condvar(results)
	local src_mac = if_nfo.mac
	local src_ip6 = packet.ip6tobin(if_nfo.address)
	local dst_mac = packet.mactobin("33:33:00:00:00:01")
	local dst_ip6 = packet.ip6tobin("ff02::1")
	local gen_qry = packet.ip6tobin("::")

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
	probe.icmpv6_payload = bin.pack("HA", "00 00 00 00", gen_qry)
	probe:build_icmpv6_header()
	probe.exheader = bin.pack("CH", packet.IPPROTO_ICMPV6, "00 05 02 00 00 01 00")
	probe.ip6_nhdr = packet.IPPROTO_HOPOPTS

	probe:build_ipv6_packet()
	probe:build_ether_frame()

	dnet:ethernet_send(probe.frame_buf)

	pcap:set_timeout(1000)
	local pcap_timeout_count = 0
	local nse_timeout = arg_timeout or 10
	local start_time = nmap:clock()
	local addrs = {}

	repeat
		local status, length, layer2, layer3 = pcap:pcap_receive()
		local cur_time = nmap:clock()
		if ( status ) then
			local l2reply = packet.Frame:new(layer2)
			local reply = packet.Packet:new(layer3, length, true)
			if ( reply.ip6_nhdr == packet.MLD_LISTENER_REPORT or 
				 reply.ip6_nhdr == packet.MLDV2_LISTENER_REPORT ) then
				local target_str = reply.ip_src
				if not results[target_str] then
					if target.ALLOW_NEW_TARGETS then
						target.add(target_str)
					end
					results[target_str] = { address = target_str, mac = stdnse.tohex(l2reply.mac_src, {separator = ":", group = 2}), iface = if_nfo.device }
				end
			end
		end
	until ( cur_time - start_time >= nse_timeout )

	dnet:ethernet_close()
	pcap:pcap_close()

	condvar("signal")
end

local function format_output(results)
	local output = tab.new()

	for _, record in pairs(results) do
		tab.addrow(output, "IP: " .. record.address, "MAC: " .. record.mac, "IFACE: " .. record.iface)
	end

	if ( #output > 0 ) then
		output = { tab.dump(output) }
		if not target.ALLOW_NEW_TARGETS then
			table.insert(output, "")
			table.insert(output, "Use --script-args=newtargets to add the results as targets")
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
		condvar "wait"
		for thread in pairs(threads) do
			if coroutine.status(thread) == "dead" then threads[thread] = nil end
		end
	until next(threads) == nil

	return format_output(results)
end

