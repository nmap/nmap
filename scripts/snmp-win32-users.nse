description = [[
Attempts to enumerate User Accounts through SNMP
]]

---
-- @output
-- | snmp-win32-users:  
-- |   Administrator
-- |   Guest
-- |   IUSR_EDUSRV011
-- |   IWAM_EDUSRV011
-- |   SUPPORT_388945a0
-- |   Tomcat
-- |   db2admin
-- |   ldaptest
-- |_  patrik


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

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl )

	local new_tab = {}

	for _, v in ipairs( tbl ) do
		table.insert( new_tab, v.value )
	end
	
	table.sort( new_tab )
	
	return new_tab
	
end

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local snmpoid = "1.3.6.1.4.1.77.1.2.25"
	local users = {}

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, "udp"))
	
	users = snmp_walk( socket, snmpoid )
	users = process_answer( users )

	if ( users == nil ) or ( #users == 0 ) then
		return
	end
	
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, users )
end

