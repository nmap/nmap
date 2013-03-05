local datafiles = require "datafiles"
local bin = require "bin"
local coroutine = require "coroutine"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

local openssl = stdnse.silent_require "openssl"

description = [[
Uses the Microsoft LLTD protocol to discover hosts on a local network.

For more information on the LLTD protocol please refer to
http://www.microsoft.com/whdc/connect/Rally/LLTD-spec.mspx
]]

---
-- @usage 
-- nmap -e <interface> --script lltd-discovery 
--
-- @args lltd-discovery.interface string specifying which interface to do lltd discovery on.  If not specified, all ethernet interfaces are tried.
-- @args lltd-discover.timeout timespec specifying how long to listen for replies (default 30s)
--
-- @output
-- | lltd-discovery: 
-- |   192.168.1.64
-- |     Hostname: acer-PC
-- |     Mac: 18:f4:6a:4f:de:a2 (Hon Hai Precision Ind. Co.)
-- |     IPv6: fe80:0000:0000:0000:0000:0000:c0a8:0134
-- |   192.168.1.33
-- |     Hostname: winxp-2b2955502
-- |     Mac: 08:00:27:79:fd:d2 (Cadmus Computer Systems)
-- |   192.168.1.22
-- |     Hostname: core
-- |     Mac: 08:00:27:57:30:7f (Cadmus Computer Systems)
-- |_  Use the newtargets script-arg to add the results as targets
--

author = "Gorjan Petrovski, Hani Benhabiles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast","discovery","safe"}


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

--- Converts a 6 byte string into the familiar MAC address formatting
-- @param mac string containing the MAC address
-- @return formatted string suitable for printing
local function get_mac_addr( mac )
	local catch = function() return end
	local try = nmap.new_try(catch)
	local mac_prefixes = try(datafiles.parse_mac_prefixes())
	
	if mac:len() ~= 6 then
		return "Unknown"
	else
		local prefix = string.upper(string.format("%02x%02x%02x", mac:byte(1), mac:byte(2), mac:byte(3)))
		local manuf = mac_prefixes[prefix] or "Unknown"
		return string.format("%02x:%02x:%02x:%02x:%02x:%02x (%s)", mac:byte(1), mac:byte(2), mac:byte(3), mac:byte(4), mac:byte(5), mac:byte(6), manuf )
	end
end

--- Gets a raw ethernet buffer with LLTD information and returns the responding host's IP and MAC
local parseHello = function(data)
-- HelloMsg = [
-- 	ethernet_hdr = [mac_dst(6), mac_src(6), protocol(2)],
--	lltd_demultiplex_hdr = [version(1), type_of_service(1), reserved(1), function(1)],
--	base_hdr = [mac_dst(6), mac_src(6), seq_no(2)],
--	up_hello_hdr = [ generation_number(2), current_mapper_address(6), apparent_mapper_address(6), tlv_list(var) ]
--]

--HelloStruct = {
--	mac_src,
--	sequence_number,
--	generation_number,
--	tlv_list(dict)
--}
	local types = {"Host ID", "Characteristics", "Physical Medium", "Wireless Mode", "802.11 BSSID", 
		"802.11 SSID", "IPv4 Address", "IPv6 Address", "802.11 Max Operational Rate", 
		"Performance Counter Frequency", nil, "Link Speed", "802.11 RSSI", "Icon Image", "Machine Name", 
		"Support Information", "Friendly Name", "Device UUID", "Hardware ID", "QoS Characteristics", 
		"802.11 Physical Medium", "AP Association Table", "Detailed Icon Image", "Sees-List Working Set",
		"Component Table", "Repeater AP Lineage", "Repeater AP Table"}
	local mac = nil
	local ipv4 = nil
	local ipv6 = nil
	local hostname = nil
	
	local pos = 1
	pos = pos + 6
	local mac_src = data:sub(pos,pos+5)
	
	pos = pos + 24
	local seq_no = data:sub(pos,pos+1)
	
	pos = pos + 2
	local generation_no = data:sub(pos,pos+1)

	pos = pos + 14
	local tlv = data:sub(pos)

	local tlv_list = {}
	local p = 1
	while p < #tlv do
		local t = tlv:byte(p) 
		if t == 0x00 then
			break
		else 
			p = p + 1
			local l = tlv:byte(p)

			p = p + 1
			local v = tlv:sub(p,p+l)
			
			if t == 0x01 then 
				-- Host ID (MAC Address)
				mac = get_mac_addr(v:sub(1,6))
			elseif t == 0x08 then
				ipv6 = string.format(
					"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					v:byte(1), v:byte(2), v:byte(3), v:byte(4), 
					v:byte(5), v:byte(6), v:byte(7), v:byte(8), 
					v:byte(9), v:byte(10), v:byte(11), v:byte(12),
					v:byte(13), v:byte(14), v:byte(15), v:byte(16))
			elseif t == 0x07 then
				-- IPv4 address
				ipv4 = string.format("%d.%d.%d.%d",v:byte(1),v:byte(2),v:byte(3),v:byte(4)), mac

			-- Machine Name (Hostname)
			elseif t == 0x0f then
			    hostname = ''
			    -- Hostname is returned in unicode, but Lua doesn't support that,
			    -- so we skip 00 values.
			    for i=1, #v-1, 2 do
				hostname = hostname .. string.char(v:byte(i))
			    end
			end

			p = p + l

			if ipv4 and ipv6 and mac and hostname then
				break
			end
		end	
	end
	 
	return ipv4, mac, ipv6, hostname 
end

--- Creates an LLTD Quick Discovery packet with the source MAC address
-- @param mac_src - six byte long binary string
local QuickDiscoveryPacket = function(mac_src)
	local ethernet_hdr, demultiplex_hdr, base_hdr, discover_up_lev_hdr

	-- set up ethernet header = [ mac_dst, mac_src, protocol ]
	local mac_dst = "FF FF FF FF FF FF" -- broadcast
	local protocol = "88 d9" -- LLTD protocol number
	
	ethernet_hdr = bin.pack("HAH",mac_dst, mac_src, protocol)
	
	-- set up LLTD demultiplex header = [ version, type_of_service, reserved, function ]
	local lltd_version = "01" -- Fixed Value
	local lltd_type_of_service = "01" -- Type Of Service = Quick Discovery(0x01)
	local lltd_reserved = "00" -- Fixed value
	local lltd_function = "00" -- Function = QuickDiscovery->Discover (0x00)

	demultiplex_hdr = bin.pack("HHHH", lltd_version, lltd_type_of_service, lltd_reserved, lltd_function )

	-- set up LLTD base header = [ mac_dst, mac_src, seq_num(xid) ]
	local lltd_seq_num = openssl.rand_bytes(2)

	base_hdr = bin.pack("HHA", mac_dst, mac_src, lltd_seq_num)

	-- set up LLTD Upper Level Header = [ generation_number, number_of_stations, station_list ]
	local generation_number = openssl.rand_bytes(2)
	local number_of_stations = "00 00"
	local station_list = "00 00 00 00 00 00 " .. "00 00 00 00 00 00 " ..
						 "00 00 00 00 00 00 " .."00 00 00 00 00 00 "
	
	discover_up_lev_hdr = bin.pack("AHH", generation_number, number_of_stations, station_list)

	-- put them all together and return
	return bin.pack("AAAA", ethernet_hdr, demultiplex_hdr, base_hdr, discover_up_lev_hdr)
end

--- Runs a thread which discovers LLTD Responders on a certain interface
local LLTDDiscover = function(if_table, lltd_responders, timeout)
	local timeout_s = 3
	local condvar = nmap.condvar(lltd_responders)
	local pcap = nmap.new_socket()
	pcap:set_timeout(5000)  	
	
	local dnet = nmap.new_dnet()
	local try = nmap.new_try(function() dnet:ethernet_close() pcap:close() end)
	
	pcap:pcap_open(if_table.device, 256, false, "")
	try(dnet:ethernet_open(if_table.device))

	local packet = QuickDiscoveryPacket(if_table.mac)
	try( dnet:ethernet_send(packet) )
	stdnse.sleep(0.5)
	try( dnet:ethernet_send(packet) )
	
	local start = os.time()
	local start_s = os.time()
	while true do
		local status, plen, l2, l3, _ = pcap:pcap_receive()
		if status then
			local packet = l2..l3
			if stdnse.tohex(packet:sub(13,14)) == "88d9" then
				start_s = os.time()
				
				local ipv4, mac, ipv6, hostname = parseHello(packet)
				
				if ipv4 then
					if not lltd_responders[ipv4] then
						lltd_responders[ipv4] = {}
						lltd_responders[ipv4].hostname = hostname
						lltd_responders[ipv4].mac = mac
						lltd_responders[ipv4].ipv6 = ipv6
					end
				end
			else
				if os.time() - start_s > timeout_s then
					break
				end
			end
		else
			break 
		end

		if os.time() - start > timeout then
			break
		end
	end
	dnet:ethernet_close()
	pcap:close()
	condvar("signal")
end


action = function()
	local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
	timeout = timeout or 30

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

	local lltd_responders={}
	local threads ={}
	local condvar = nmap.condvar(lltd_responders)

	-- party time 
	for _, if_table in ipairs(interfaces) do
		-- create a thread for each interface
		local co = stdnse.new_thread(LLTDDiscover, if_table, lltd_responders, timeout)
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
	local output = {}
	for ip_addr, info in pairs(lltd_responders) do
	    if target.ALLOW_NEW_TARGETS then target.add(ip_addr) end

	    local s = {}
	    s.name = ip_addr
	    if info.hostname then	
		table.insert(s, "Hostname: " .. info.hostname)
	    end
	    if info.mac then	
		table.insert(s, "Mac: " .. info.mac)
	    end
	    if info.ipv6 then	
		table.insert(s, "IPv6: " .. info.ipv6)
	    end
	    table.insert(output,s)
	end

	if #output>0 and not target.ALLOW_NEW_TARGETS then
	    table.insert(output,"Use the newtargets script-arg to add the results as targets")
	end
	return stdnse.format_output( (#output>0), output )
end
