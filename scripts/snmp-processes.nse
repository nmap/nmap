description = [[
Attempts to enumerate running processes through SNMP
]]

---
-- @output
-- | snmp-processes:  
-- |   System Idle Process
-- |     PID: 1
-- |   System
-- |     PID: 4
-- |   smss.exe
-- |     Path: \SystemRoot\System32\
-- |     PID: 256
-- |   csrss.exe
-- |     Path: C:\WINDOWS\system32\
-- |     Params: ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserS
-- |     PID: 308
-- |   winlogon.exe
-- |     PID: 332
-- |   services.exe
-- |     Path: C:\WINDOWS\system32\
-- |     PID: 380
-- |   lsass.exe
-- |     Path: C:\WINDOWS\system32\
-- |_    PID: 392

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occure if a mib did not exist
-- Revised 01/19/2010 - v0.2 - removed debugging output and renamed file

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
	
	local swrun_name = "1.3.6.1.2.1.25.4.2.1.2"
	local swrun_pid = "1.3.6.1.2.1.25.4.2.1.1"
	local swrun_path = "1.3.6.1.2.1.25.4.2.1.4"
	local swrun_params = "1.3.6.1.2.1.25.4.2.1.5"
	local new_tbl = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. swrun_name) ) then
			local item = {}			
			local objid = v.oid:gsub( "^" .. swrun_name, swrun_path) 
			local value =  get_value_from_table( tbl, objid )
			
			if value and value:len() > 0 then
				table.insert( item, ("Path: %s"):format( value ) )
			end
			
			objid = v.oid:gsub( "^" .. swrun_name, swrun_params) 
			value = get_value_from_table( tbl, objid )
			
			if value and value:len() > 0 then
				table.insert( item, ("Params: %s"):format( value ) )
			end
	
			objid = v.oid:gsub( "^" .. swrun_name, swrun_pid) 
			value = get_value_from_table( tbl, objid )
			
			if value then
				table.insert( item, ("PID: %s"):format( value ) )
			end
			
			item.name = v.value
			table.insert( item, value )
			table.insert( new_tbl, item )
		end
	
	end
	
	return new_tbl
	
end


action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local data, snmpoid = nil, "1.3.6.1.2.1.25.4.2"
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

