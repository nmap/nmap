description = [[
Attempts to enumerate Windows Shares through SNMP
]]

---
-- @output
-- | snmp-win32-shares:  
-- |   SYSVOL
-- |     C:\WINDOWS\sysvol\sysvol
-- |   NETLOGON
-- |     C:\WINDOWS\sysvol\sysvol\inspectit-labb.local\SCRIPTS
-- |   Webapps
-- |_    C:\Program Files\Apache Software Foundation\Tomcat 5.5\webapps\ROOT

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
-- @param base_oid string containing the base object ID to walk
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
	
	local share_name = "1.3.6.1.4.1.77.1.2.27.1.1"
	local share_path = "1.3.6.1.4.1.77.1.2.27.1.2"
	local new_tbl = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. share_name) ) then
			local item = {}
			local objid = v.oid:gsub( "^" .. share_name, share_path) 
			local path = get_value_from_table( tbl, objid )

			item.name = v.value
			table.insert( item, path )
			table.insert( new_tbl, item )
		end
	
	end
	
	return new_tbl
	
end


action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local data, snmpoid = nil, "1.3.6.1.4.1.77.1.2.27"
	local shares = {}

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, "udp"))
	
	shares = snmp_walk( socket, snmpoid )

	if ( shares == nil ) or ( #shares == 0 ) then
		return
	end
		
	shares = process_answer( shares )

	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, shares )
end

