description = [[
Attempts to enumerate installed software through SNMP
]]

---
-- @output
-- | snmp-win32-software:  
-- |   Apache Tomcat 5.5 (remove only); 2007-09-15 15:13:18
-- |   Microsoft Internationalized Domain Names Mitigation APIs; 2007-09-15 15:13:18
-- |   Security Update for Windows Media Player (KB911564); 2007-09-15 15:13:18
-- |   Security Update for Windows Server 2003 (KB924667-v2); 2007-09-15 15:13:18
-- |   Security Update for Windows Media Player 6.4 (KB925398); 2007-09-15 15:13:18
-- |   Security Update for Windows Server 2003 (KB925902); 2007-09-15 15:13:18
-- |_  Windows Internet Explorer 7; 2007-09-15 15:13:18

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.2
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occure if a mib did not exist

require "shortport"
require "snmp"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})


--- Walks the MIB Tree
--
-- @param socket socket already connected to the server
-- @base_oid string containing the base object ID to walk
-- @return table containing <code>oid</code> and <code>value</code>
function snmp_walk( socket, base_oid )
	
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	

	local snmp_table = {}
	local oid = base_oid
	
	while ( true ) do
		
		local value, response, snmpdata, options, item = nil, nil, nil, {}, {}
		options.reqId = 28428 -- unnecessary?
		payload = snmp.encode( snmp.buildPacket( snmp.buildGetNextRequest(options, oid) ) )

		try(socket:send(payload))
		response = try( socket:receive_bytes(1) )
	
		snmpdata = snmp.fetchResponseValues( response )
		
		value = snmpdata[1][1]
		oid  = snmpdata[1][2]
		
		if not oid:match( base_oid ) or base_oid == oid then
			break
		end
		
		item.oid = oid
		item.value = value
		
		table.insert( snmp_table, item )
		
	end

	socket:close()
	snmp_table.baseoid = base_oid

	return snmp_table
	
end

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

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl )
	
	local sw_name = "1.3.6.1.2.1.25.6.3.1.2"
	local sw_date = "1.3.6.1.2.1.25.6.3.1.5"
	local new_tbl = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. sw_name) ) then
			local objid = v.oid:gsub( "^" .. sw_name, sw_date) 
			local install_date = get_value_from_table( tbl, objid )
			local sw_item
			
			local _, year, month, day, hour, min, sec = bin.unpack( ">SCCCCC", install_date )
			install_date = ("%02d-%02d-%02d %02d:%02d:%02d"):format( year, month, day, hour, min, sec )	

			sw_item = ("%s; %s"):format(v.value ,install_date)
			table.insert( new_tbl, sw_item )
		end
	
	end
	
	table.sort( new_tbl )
	return new_tbl
	
end


action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local data, snmpoid = nil, "1.3.6.1.2.1.25.6.3.1"
	local sw = {}

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, "udp"))
	
	sw = snmp_walk( socket, snmpoid )

	if ( sw == nil ) or ( #sw == 0 ) then
		return
	end
		
	sw = process_answer( sw )

	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, sw )
end

