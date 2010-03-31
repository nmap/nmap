description = [[
Attempts to query SNMP for a netstat like output
]]

---
-- @output
-- | snmp-netstat:  
-- |   TCP  0.0.0.0:21           0.0.0.0:2256
-- |   TCP  0.0.0.0:80           0.0.0.0:8218
-- |   TCP  0.0.0.0:135          0.0.0.0:53285
-- |   TCP  0.0.0.0:389          0.0.0.0:38990
-- |   TCP  0.0.0.0:445          0.0.0.0:49158
-- |   TCP  127.0.0.1:389        127.0.0.1:1045
-- |   TCP  127.0.0.1:389        127.0.0.1:1048
-- |   UDP  192.168.56.3:137     *:*
-- |   UDP  192.168.56.3:138     *:*
-- |   UDP  192.168.56.3:389     *:*
-- |_  UDP  192.168.56.3:464     *:*

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.1
-- Created 01/19/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

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
		
		local lip = oid:match( "^" .. base_oid .. "%.(%d+%.%d+%.%d+%.%d+)") or ""
		local lport = oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.(%d+)")
		local fip = oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+%.%d+%.%d+%.%d+)") or "*:*"
		local fport = oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+)")
		
		if lport and lport ~= "0" then
			lip = lip .. ":" .. lport
		end
		
		if fport and fport ~= "0" then
			fip = fip .. ":" .. fport
		end
		
		
		value = string.format("%-20s %s", lip, fip )
		
		item.oid = oid
		item.value = value

		table.insert( snmp_table, item )
		
	end

	snmp_table.baseoid = base_oid
	
	return snmp_table
	
end

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl, prefix )

	local new_tab = {}

	for _, v in ipairs( tbl ) do
		table.insert( new_tab, string.format( "%-4s %s", prefix, v.value ) )
	end
		
	return new_tab
	
end

function table_merge( t1, t2 )
	for _, v in ipairs(t2) do
		table.insert(t1, v)
	end

	return t1
end

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local tcp_oid = "1.3.6.1.2.1.6.13.1.1"
	local udp_oid = "1.3.6.1.2.1.7.5.1.1"
	local netstat = {}

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, "udp"))
	
	local tcp = snmp_walk( socket, tcp_oid )
	local udp = snmp_walk( socket, udp_oid )

	if ( tcp == nil ) or ( #tcp == 0 ) or ( udp==nil ) or ( #udp == 0 ) then
		return
	end
	
	tcp = process_answer(tcp, "TCP")
	udp = process_answer(udp, "UDP")
	netstat = table_merge( tcp, udp )
	
	nmap.set_port_state(host, port, "open")
	socket:close()

	return stdnse.format_output( true, netstat )
end

