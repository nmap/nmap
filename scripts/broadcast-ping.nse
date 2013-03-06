local bin = require "bin"
local coroutine = require "coroutine"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local target = require "target"

local openssl = stdnse.silent_require "openssl"

description = [[
Sends broadcast pings on a selected interface using raw ethernet packets and 
outputs the responding hosts' IP and MAC addresses or (if requested) adds them as targets.  Root privileges on UNIX are required to run this script since it uses raw sockets.  Most operating systems don't respond to broadcast-ping probes, 
but they can be configured to do so.

The interface on which is broadcasted can be specified using the -e Nmap option
or the <code>broadcast-ping.interface</code> script-arg. If no interface is 
specified this script broadcasts on all ethernet interfaces which have an IPv4
address defined.

The <code>newtarget</code> script-arg can be used so the script adds the 
discovered IPs as targets.

The timeout of the ICMP probes can be specified using the <code>timeout</code>
script-arg. The default timeout is 3000 ms. A higher number might be necesary 
when scanning across larger networks.

The number of sent probes can be specified using the <code>num-probes</code>
script-arg. The default number is 1. A higher value might get more results on 
larger networks.

The ICMP probes sent comply with the --ttl and --data-length Nmap options, so 
you can use those to control the TTL(time to live) and ICMP payload length 
respectively. The default value for TTL is 64, and the length of the payload 
is 0. The payload is consisted of random bytes.
]]

---
-- @usage
-- nmap -e <interface> [--ttl <ttl>] [--data-length <payload_length>]
-- --script broadcast-ping [--script-args [broadcast-ping.timeout=<ms>],[num-probes=<n>]]
--
-- @args broadcast-ping.interface string specifying which interface to use for this script (default all interfaces)
-- @args broadcast-ping.num_probes number specifying how many ICMP probes should be sent (default 1)
-- @args broadcast-ping.timeout timespec specifying how long to wait for response (default 3s)
--
-- @output
-- | broadcast-ping: 
-- |   IP: 192.168.1.1    MAC: 00:23:69:2a:b1:25 
-- |   IP: 192.168.1.106  MAC: 1c:65:9d:88:d8:36
-- |_  Use --script-args=newtargets to add the results as targets
--
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","safe","broadcast"}


prerule = function()
	if not nmap.is_privileged() then
		nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
		if not nmap.registry[SCRIPT_NAME].rootfail then
			stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
		end
		nmap.registry[SCRIPT_NAME].rootfail = true
		return nil
	end
	
	if nmap.address_family() ~= 'inet' then
		stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
		return false
	end
	
	return true
end


--- ICMP packet crafting
--
-- @param srcIP string containing the source IP, IPv4 format
-- @param dstIP string containing the destination IP, IPv4 format
-- @param ttl number containing value for the TTL (time to live) field in IP header
-- @param data_length number value of ICMP payload length 
local icmp_packet = function(srcIP, dstIP, ttl, data_length, mtu, seqNo, icmp_id)
	-- A couple of checks first
	assert((seqNo and seqNo>0 and seqNo<=0xffff),"ICMP Sequence number: Value out of range(1-65535).")
	assert((ttl and ttl>0 and ttl<0xff),"TTL(time-to-live): Value out of range(1-256).")
	-- MTU values should be considered here!
	assert((data_length and data_length>=0 and data_length<mtu),"ICMP Payload length: Value out of range(0-mtu).")
	
	-- ICMP Message
	local icmp_payload = nil
	if data_length and data_length>0 then
		icmp_payload = openssl.rand_bytes(data_length)
	else
		icmp_payload = ""
	end
	
	local seqNo_hex = stdnse.tohex(seqNo)
	local icmp_seqNo = bin.pack(">H", string.rep("0",(4-seqNo_hex))..seqNo_hex)

	-- Type=08; Code=00; Chksum=0000; ID=icmp_id; SeqNo=icmp_seqNo; Payload=icmp_payload(hex string);
	local icmp_tmp = bin.pack(">HAAA", "0800 0000", icmp_id, icmp_seqNo, icmp_payload)
	
	local icmp_checksum = packet.in_cksum(icmp_tmp)
	
	local icmp_msg = bin.pack(">HHAAA", "0800", stdnse.tohex(icmp_checksum), icmp_id, icmp_seqNo, icmp_payload)
	
	
	--IP Total Length
	local length_hex =  stdnse.tohex(20 + #icmp_msg)
	local ip_length = bin.pack(">H", string.rep("0",(4-#length_hex))..length_hex)
	
	--TTL
	local ttl_hex = stdnse.tohex(ttl)
	local ip_ttl = bin.pack(">H", string.rep("0",(2-ttl_hex))..ttl_hex)
	
	--IP header
	local ip_bin = bin.pack(">HAHAH","4500",ip_length, "0000 4000", ip_ttl,
		"01 0000 0000 0000 0000 0000")
	
	-- IP+ICMP; Addresses and checksum need to be filled
	local icmp_bin = bin.pack(">AA",ip_bin, icmp_msg)
	
	--Packet
	local icmp = packet.Packet:new(icmp_bin,#icmp_bin)
	assert(icmp,"Mistake during ICMP packet parsing")
	
	icmp:ip_set_bin_src(packet.iptobin(srcIP))
	icmp:ip_set_bin_dst(packet.iptobin(dstIP))
	icmp:ip_count_checksum()
	
	return icmp
end

local broadcast_if = function(if_table,icmp_responders)
	local condvar = nmap.condvar(icmp_responders)
	
	local num_probes = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".num-probes")) or 1
	
	local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
	timeout =	(timeout or 3) * 1000
	
	local ttl = nmap.get_ttl()
	
	local data_length = nmap.get_payload_length()
	local sequence_number = 1
	local destination_IP = "255.255.255.255"

	-- raw IPv4 socket 
	local dnet = nmap.new_dnet()
	local try = nmap.new_try()
	try = nmap.new_try(function() dnet:ethernet_close() end)
	
	-- raw sniffing socket (icmp echoreply style)
	local pcap = nmap.new_socket()
	pcap:set_timeout(timeout)

	local mtu = if_table.mtu or 256  -- 256 is minimal mtu
		
	pcap:pcap_open(if_table.device, 104, false, "dst host ".. if_table.address ..
		" and icmp[icmptype]==icmp-echoreply")
	try(dnet:ethernet_open(if_table.device))
	
	local source_IP = if_table.address 
	
	local icmp_ids = {}

	for i = 1, num_probes do
		-- ICMP packet
		local icmp_id = openssl.rand_bytes(2)
		icmp_ids[icmp_id]=true
		local icmp = icmp_packet( source_IP, destination_IP, ttl, 
			data_length, mtu, sequence_number, icmp_id)
		
		local ethernet_icmp = bin.pack("HAHA", "FF FF FF FF FF FF", if_table.mac, "08 00", icmp.buf)

		try( dnet:ethernet_send(ethernet_icmp) )
	end

	while true do
		local status, plen, l2, l3data, _ = pcap:pcap_receive() 
		if not status then break end
		
		-- Do stuff with packet
		local icmpreply = packet.Packet:new(l3data,plen,false)
		-- We check whether the packet is parsed ok, and whether the ICMP ID of the sent packet
		-- is the same with the ICMP ID of the received packet. We don't want ping probes interfering
		local icmp_id = icmpreply:raw(icmpreply.icmp_offset+4,2) 
		if icmpreply:ip_parse() and icmp_ids[icmp_id] then 
			if not icmp_responders[icmpreply.ip_src] then
				-- [key = IP]=MAC
				local mac_pretty = string.format("%02x:%02x:%02x:%02x:%02x:%02x",l2:byte(7),
					l2:byte(8),l2:byte(9),l2:byte(10),l2:byte(11),l2:byte(12))
				icmp_responders[icmpreply.ip_src] = mac_pretty
			end
		else
			stdnse.print_debug("Erroneous ICMP packet received; Cannot parse IP header.")
		end
	end

	pcap:close()
	dnet:ethernet_close()
	
	condvar "signal"
end


action = function() 
	
	--get interface script-args, if any
	local interface_arg = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
	local interface_opt = nmap.get_interface()
	
	-- interfaces list (decide which interfaces to broadcast on)
	local interfaces ={}
	if interface_opt or interface_arg then
		-- single interface defined
		local interface = interface_opt or interface_arg
		local if_table = nmap.get_interface_info(interface)
		if not if_table or not if_table.address or not if_table.link=="ethernet" then
			stdnse.print_debug("Interface not supported or not properly configured.")
			return false
		end
		table.insert(interfaces, if_table)
	else
		local tmp_ifaces = nmap.list_interfaces()
		for _, if_table in ipairs(tmp_ifaces) do
			if if_table.address and 
				if_table.link=="ethernet" and 
				if_table.address:match("%d+%.%d+%.%d+%.%d+") then
				table.insert(interfaces, if_table)
			end
		end
	end
	
	if #interfaces == 0 then 
		stdnse.print_debug("No interfaces found.")
		return 
	end

	local icmp_responders={}
	local threads ={}
	local condvar = nmap.condvar(icmp_responders)

	-- party time 
	for _, if_table in ipairs(interfaces) do
		-- create a thread for each interface
		local co = stdnse.new_thread(broadcast_if, if_table, icmp_responders)
		threads[co]=true
	end

	repeat
		for thread in pairs(threads) do
			if coroutine.status(thread) == "dead" then threads[thread] = nil end
		end
		if ( next(threads) ) then
			condvar "wait"
		end
	until next(threads) == nil
	
	-- generate output
	local output = tab.new()
	for ip_addr, mac_addr in pairs(icmp_responders) do
		if target.ALLOW_NEW_TARGETS then
			target.add(ip_addr)
		end
		tab.addrow(output, "IP: " .. ip_addr, "MAC: " .. mac_addr)
	end
	if #output > 0 then
		output = { tab.dump(output) }
		if not target.ALLOW_NEW_TARGETS then
			output[#output + 1] = "Use --script-args=newtargets to add the results as targets"
		end
		return stdnse.format_output(true, output)
	end
end
