local datafiles = require "datafiles"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to enumerate network interfaces through SNMP.

This script can also be run during Nmap's pre-scanning phase and can
attempt to add the SNMP server's interface addresses to the target
list.  The script argument <code>snmp-interfaces.host</code> is
required to know what host to probe.  To specify a port for the SNMP
server other than 161, use <code>snmp-interfaces.port</code>.  When
run in this way, the script's output tells how many new targets were
successfully added.
]]

---
-- @args snmp-interfaces.host  Specifies the SNMP server to probe when
--       running in the "pre-scanning phase".
-- @args snmp-interfaces.port  The optional port number corresponding
--       to the host script argument.  Defaults to 161.
--
-- @output
-- | snmp-interfaces:
-- |   eth0
-- |     IP address: 192.168.221.128
-- |     MAC address: 00:0c:29:01:e2:74 (VMware)
-- |     Type: ethernetCsmacd  Speed: 1 Gbps
-- |_    Traffic stats: 6.45 Mb sent, 15.01 Mb received
--

author = "Thomas Buchanan, Kris Katterjohn"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- code borrowed heavily from Patrik Karlsson's excellent snmp scripts
-- Created 03/03/2010 - v0.1 - created by Thomas Buchanan <tbuchanan@thecompassgrp.net>
-- Revised 03/05/2010 - v0.2 - Reworked output slighty, moved iana_types to script scope. Suggested by David Fifield
-- Revised 04/11/2010 - v0.2 - moved snmp_walk to snmp library <patrik@cqure.net>
-- Revised 08/10/2010 - v0.3 - prerule; add interface addresses to Nmap's target list (Kris Katterjohn)
-- Revised 05/27/2011 - v0.4 - action; add MAC addresses to nmap.registry[host.ip]["mac-geolocation"] (Gorjan Petrovski)
-- Revised 07/31/2012 - v0.5 - action; remove mac-geolocation changes (script removed from trunk)




prerule = function()
	if not stdnse.get_script_args({"snmp-interfaces.host", "host"}) then
		stdnse.print_debug(3,
			"Skipping '%s' %s, 'snmp-interfaces.host' argument is missing.",
			SCRIPT_NAME, SCRIPT_TYPE)
		return false
	end

        return true
end

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

-- List of IANA-assigned network interface types
-- Taken from IANAifType-MIB 
-- Available at http://www.iana.org/assignments/ianaiftype-mib
-- REVISION     "201002110000Z"
local iana_types = { "other", "regular1822", "hdh1822", "ddnX25", "rfc877x25", "ethernetCsmacd", 
	"iso88023Csmacd", "iso88024TokenBus", "iso88025TokenRing", "iso88026Man", "starLan",
	"proteon10Mbit", "proteon80Mbit", "hyperchannel", "fddi", "lapb", "sdlc", "ds1", "e1", 
	"basicISDN", "primaryISDN", "propPointToPointSerial", "ppp", "softwareLoopback", "eon", 
	"ethernet3Mbit", "nsip", "slip", "ultra", "ds3", "sip", "frameRelay", "rs232", "para", 
	"arcnet", "arcnetPlus", "atm", "miox25", "sonet", "x25ple", "iso88022llc", "localTalk", 
	"smdsDxi", "frameRelayService", "v35", "hssi", "hippi", "modem", "aal5", "sonetPath", 
	"sonetVT", "smdsIcip", "propVirtual", "propMultiplexor", "ieee80212", "fibreChannel", 
	"hippiInterface", "frameRelayInterconnect", "aflane8023", "aflane8025", "cctEmul", 
	"fastEther", "isdn", "v11", "v36", "g703at64k", "g703at2mb", "qllc", "fastEtherFX", 
	"channel", "ieee80211", "ibm370parChan", "escon", "dlsw", "isdns", "isdnu", "lapd", 
	"ipSwitch", "rsrb", "atmLogical", "ds0", "ds0Bundle", "bsc", "async", "cnr", 
	"iso88025Dtr", "eplrs", "arap", "propCnls", "hostPad", "termPad", "frameRelayMPI", 
	"x213", "adsl", "radsl", "sdsl", "vdsl", "iso88025CRFPInt", "myrinet", "voiceEM", 
	"voiceFXO", "voiceFXS", "voiceEncap", "voiceOverIp", "atmDxi", "atmFuni", "atmIma", 
	"pppMultilinkBundle", "ipOverCdlc", "ipOverClaw", "stackToStack", "virtualIpAddress", 
	"mpc", "ipOverAtm", "iso88025Fiber", "tdlc", "gigabitEthernet", "hdlc", "lapf", "v37", 
	"x25mlp", "x25huntGroup", "trasnpHdlc", "interleave", "fast", "ip", "docsCableMaclayer", 
	"docsCableDownstream", "docsCableUpstream", "a12MppSwitch", "tunnel", "coffee", "ces", 
	"atmSubInterface", "l2vlan", "l3ipvlan", "l3ipxvlan", "digitalPowerlinev", "mediaMailOverIp", 
	"dtm", "dcn", "ipForward", "msdsl", "ieee1394", "if-gsn", "dvbRccMacLayer", "dvbRccDownstream", 
	"dvbRccUpstream", "atmVirtual", "mplsTunnel", "srp", "voiceOverAtm", "voiceOverFrameRelay", 
	"idsl", "compositeLink", "ss7SigLink", "propWirelessP2P", "frForward", "rfc1483", "usb", 
	"ieee8023adLag", "bgppolicyaccounting", "frf16MfrBundle", "h323Gatekeeper", "h323Proxy", 
	"mpls", "mfSigLink", "hdsl2", "shdsl", "ds1FDL", "pos", "dvbAsiIn", "dvbAsiOut", "plc", 
	"nfas", "tr008", "gr303RDT", "gr303IDT", "isup", "propDocsWirelessMaclayer", 
	"propDocsWirelessDownstream", "propDocsWirelessUpstream", "hiperlan2", "propBWAp2Mp", 
	"sonetOverheadChannel", "digitalWrapperOverheadChannel", "aal2", "radioMAC", "atmRadio", 
	"imt", "mvl", "reachDSL", "frDlciEndPt", "atmVciEndPt", "opticalChannel", "opticalTransport", 
	"propAtm", "voiceOverCable", "infiniband", "teLink", "q2931", "virtualTg", "sipTg", "sipSig", 
	"docsCableUpstreamChannel", "econet", "pon155", "pon622", "bridge", "linegroup", "voiceEMFGD", 
	"voiceFGDEANA", "voiceDID", "mpegTransport", "sixToFour", "gtp", "pdnEtherLoop1", 
	"pdnEtherLoop2", "opticalChannelGroup", "homepna", "gfp", "ciscoISLvlan", "actelisMetaLOOP", 
	"fcipLink", "rpr", "qam", "lmp", "cblVectaStar", "docsCableMCmtsDownstream", "adsl2", 
	"macSecControlledIF", "macSecUncontrolledIF", "aviciOpticalEther", "atmbond", "voiceFGDOS", 
	"mocaVersion1", "ieee80216WMAN", "adsl2plus", "dvbRcsMacLayer", "dvbTdm", "dvbRcsTdma", 
	"x86Laps", "wwanPP", "wwanPP2", "voiceEBS", "ifPwType", "ilan", "pip", "aluELP", "gpon", 
	"vdsl2", "capwapDot11Profile", "capwapDot11Bss", "capwapWtpVirtualRadio" }

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
function get_value_from_table( tbl, oid )
	
	for _, v in ipairs( tbl ) do
		if v.oid == oid then
			return v.value
		end
	end
	
	return nil
end

--- Gets the network interface type from a list of IANA approved types
--
-- @param iana integer interface type returned from snmp result
-- @return string description of interface type, or "Unknown" if type not found
function get_iana_type( iana )
	-- 254 types are currently defined
	-- if the requested type falls outside that range, reset to "other"
	if iana > 254 or iana < 1 then
		iana = 1
	end
	
	return iana_types[iana]
end

--- Calculates the speed of the interface based on the snmp value
-- 
-- @param speed value from IF-MIB::ifSpeed
-- @return string description of speed
function get_if_speed( speed )
	local result
	
	-- GigE or 10GigE speeds
	if speed >= 1000000000 then
		result = string.format( "%d Gbps", speed / 1000000000)
	-- Common for 10 or 100 Mbit ethernet
	elseif speed >= 1000000 then
		result = string.format( "%d Mbps", speed / 1000000)
	-- Anything slower report in Kbps
	else
		result = string.format( "%d Kbps", speed / 1000)
	end
	
	return result
end

--- Calculates the amount of traffic passed through an interface based on the snmp value
-- 
-- @param amount value from IF-MIB::ifInOctets or IF-MIB::ifOutOctets
-- @return string description of traffic amount
function get_traffic( amount )
	local result
	
	-- Gigabytes
	if amount >= 1000000000 then
		result = string.format( "%.2f Gb", amount / 1000000000)
	-- Megabytes
	elseif amount >= 1000000 then
		result = string.format( "%.2f Mb", amount / 1000000)
	-- Anything lower report in kb
	else
		result = string.format( "%.2f Kb", amount / 1000)
	end
	
	return result
end

--- Converts a 6 byte string into the familiar MAC address formatting
--
-- @param mac string containing the MAC address
-- @return formatted string suitable for printing
function get_mac_addr( mac )
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

--- Processes the list of network interfaces
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table with network interfaces described in key / value pairs
function process_interfaces( tbl )
	
	-- Add the %. escape character to prevent matching the index on e.g. "1.3.6.1.2.1.2.2.1.10."
	local if_index = "1.3.6.1.2.1.2.2.1.1%."
	local if_descr = "1.3.6.1.2.1.2.2.1.2."
	local if_type = "1.3.6.1.2.1.2.2.1.3."
	local if_speed = "1.3.6.1.2.1.2.2.1.5."
	local if_phys_addr = "1.3.6.1.2.1.2.2.1.6."
	local if_status = "1.3.6.1.2.1.2.2.1.8."
	local if_in_octets = "1.3.6.1.2.1.2.2.1.10."
	local if_out_octets = "1.3.6.1.2.1.2.2.1.16."
	local new_tbl = {}
	
	-- Some operating systems (such as MS Windows) don't list interfaces with consecutive indexes
	-- Therefore we keep an index list so we can iterate over the indexes later on
	new_tbl.index_list = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. if_index) ) then
			local item = {}
			item.index = get_value_from_table( tbl, v.oid )
			
			local objid = v.oid:gsub( "^" .. if_index, if_descr) 
			local value = get_value_from_table( tbl, objid )
			
			if value and value:len() > 0 then
				item.descr = value
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_type ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.type = get_iana_type(value)
			end
	
			objid = v.oid:gsub( "^" .. if_index, if_speed ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.speed = get_if_speed( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_phys_addr ) 
			value = get_value_from_table( tbl, objid )
						
			if value and value:len() > 0 then
				item.phys_addr = get_mac_addr( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_status ) 
			value = get_value_from_table( tbl, objid )
			
			if value == 1 then
				item.status = "up"
			elseif value == 2 then
				item.status = "down"
			end
	
			objid = v.oid:gsub( "^" .. if_index, if_in_octets ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.received = get_traffic( value )
			end
			
			objid = v.oid:gsub( "^" .. if_index, if_out_octets ) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				item.sent = get_traffic( value )
			end
				
			new_tbl[item.index] = item
			-- Add this interface index to our master list
			table.insert( new_tbl.index_list, item.index )
			
		end
	
	end
	
	return new_tbl
	
end

--- Processes the list of network interfaces and finds associated IP addresses
--
-- @param if_tbl table containing network interfaces
-- @param ip_tbl table containing <code>oid</code> and <code>value</code> pairs from IP::MIB
-- @return table with network interfaces described in key / value pairs
function process_ips( if_tbl, ip_tbl )
	local ip_index = "1.3.6.1.2.1.4.20.1.2."
	local ip_addr = "1.3.6.1.2.1.4.20.1.1."
	local ip_netmask = "1.3.6.1.2.1.4.20.1.3."
	local index
	local item
	
	for _, v in ipairs( ip_tbl ) do
		if ( v.oid:match("^" .. ip_index) ) then
			index = get_value_from_table( ip_tbl, v.oid )
			item = if_tbl[index]
			
			local objid = v.oid:gsub( "^" .. ip_index, ip_addr ) 
			local value = get_value_from_table( ip_tbl, objid )
			
			if value then
				item.ip_addr = value
			end
			
			objid = v.oid:gsub( "^" .. ip_index, ip_netmask ) 
			value = get_value_from_table( ip_tbl, objid )
			
			if value then
				item.netmask = value
			end
		end
	end
	
	return if_tbl
end

--- Creates a table of IP addresses from the table of network interfaces
--
-- @param tbl table containing network interfaces
-- @return table containing only IP addresses
function list_addrs( tbl )
	local new_tbl = {}

	for _, index in ipairs( tbl.index_list ) do
		local interface = tbl[index]
		if interface.ip_addr then
			table.insert( new_tbl, interface.ip_addr )
		end
	end

	return new_tbl
end

--- Process the table of network interfaces for reporting
--
-- @param tbl table containing network interfaces
-- @return table suitable for <code>stdnse.format_output</code>
function build_results( tbl )
	local new_tbl = {}
	local verbose = nmap.verbosity()
	
	-- For each interface index previously discovered, format the relevant information for output
	for _, index in ipairs( tbl.index_list ) do
		local interface = tbl[index]
		local item = {}
		local status = interface.status
		local if_type = interface.type
		
		if interface.descr then
			item.name = interface.descr
		else
			item.name = string.format("Interface %d", index)
		end
		
		if interface.ip_addr and interface.netmask then
			table.insert( item, ("IP address: %s  Netmask: %s"):format( interface.ip_addr, interface.netmask ) )
		end
		
		if interface.phys_addr then
			table.insert( item, ("MAC address: %s"):format( interface.phys_addr ) )
		end
		
		if interface.type and interface.speed then
			table.insert( item, ("Type: %s  Speed: %s"):format( interface.type, interface.speed ) )
		end
		
		if ( verbose > 0 ) and interface.status then
			table.insert( item, ("Status: %s"):format( interface.status ) )
		end
		
		if interface.sent and interface.received then
			table.insert( item, ("Traffic stats: %s sent, %s received"):format( interface.sent, interface.received ) )
		end
		
		if ( verbose > 0 ) or status == "up" then
			table.insert( new_tbl, item )
		end
	end
	
	return new_tbl
end		

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	-- IF-MIB - used to look up network interfaces
	local if_oid = "1.3.6.1.2.1.2.2.1"
	-- IP-MIB - used to determine IP address information
	local ip_oid = "1.3.6.1.2.1.4.20"
	local interfaces = {}
	local ips = {}
	local status
	local srvhost, srvport
	
	if SCRIPT_TYPE == "prerule" then
		srvhost = stdnse.get_script_args({"snmp-interfaces.host", "host"})
		if not srvhost then
			-- Shouldn't happen; checked in prerule.
			return
		end

		srvport = stdnse.get_script_args({"snmp-interfaces.port", "port"})
		if srvport then
			srvport = tonumber(srvport)
		else
			srvport = 161
		end
	else
		srvhost = host.ip
		srvport = port.number
	end

	socket:set_timeout(5000)
	try(socket:connect(srvhost, srvport, "udp"))
	
	-- retreive network interface information from IF-MIB
	status, interfaces = snmp.snmpWalk( socket, if_oid )
	socket:close()
	
	if (not(status)) or ( interfaces == nil ) or ( #interfaces == 0 ) then
		return
	end
	
	stdnse.print_debug("SNMP walk of IF-MIB returned %d lines", #interfaces)
	
	-- build a table of network interfaces from the IF-MIB table
	interfaces = process_interfaces( interfaces )
	
	-- retreive IP address information from IP-MIB
	try(socket:connect(srvhost, srvport, "udp"))
	status, ips = snmp.snmpWalk( socket, ip_oid )
	
	-- associate that IP address information with the correct interface
	if (not(status)) or ( ips ~= nil ) and ( #ips ~= 0 ) then
		interfaces = process_ips( interfaces, ips )
	end

	local output = stdnse.format_output( true, build_results(interfaces) )
	
	if SCRIPT_TYPE == "prerule" and target.ALLOW_NEW_TARGETS then
		local sum = 0

		ips = list_addrs(interfaces)

		-- Could add all of the addresses at once, but count
		-- successful additions instead for script output
		for _, i in ipairs(ips) do
			local st, err = target.add(i)
			if st then
				sum = sum + 1
			else
				stdnse.print_debug("Couldn't add target " .. i .. ": " .. err)
			end
		end

		if sum ~= 0 then
			output = output .. "\nSuccessfully added " .. tostring(sum) .. " new targets"
		end
	elseif SCRIPT_TYPE == "portrule" then
		nmap.set_port_state(host, port, "open")
	end

	return output
end

