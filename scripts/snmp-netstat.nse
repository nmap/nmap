description = [[
Attempts to query SNMP for a netstat like output.
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

-- Version 0.2
-- Created 01/19/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 04/11/2010 - v0.2 - moved snmp_walk to snmp library <patrik@cqure.net>

require "shortport"
require "snmp"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param prefix string containing either "UDP" or "TCP"
-- @param base_oid string containing the value of the base_oid of the walk
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl, prefix, base_oid )

	local new_tab = {}

	for _, v in ipairs( tbl ) do
		local lip = v.oid:match( "^" .. base_oid .. "%.(%d+%.%d+%.%d+%.%d+)") or ""
		local lport = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.(%d+)")
		local fip = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+%.%d+%.%d+%.%d+)") or "*:*"
		local fport = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+)")
		local value
		
		if lport and lport ~= "0" then
			lip = lip .. ":" .. lport
		end
		
		if fport and fport ~= "0" then
			fip = fip .. ":" .. fport
		end
		
		
		value = string.format("%-20s %s", lip, fip )
		table.insert( new_tab, string.format( "%-4s %s", prefix, value ) )
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
	local status, tcp, udp

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, tcp = snmp.snmpWalk( socket, tcp_oid )
	if ( not(status) ) then return end

	status, udp = snmp.snmpWalk( socket, udp_oid )
	if ( not(status) ) then return end
	socket:close()
	
	if ( tcp == nil ) or ( #tcp == 0 ) or ( udp==nil ) or ( #udp == 0 ) then
		return
	end
	
	tcp = process_answer(tcp, "TCP", tcp_oid)
	udp = process_answer(udp, "UDP", udp_oid)
	netstat = table_merge( tcp, udp )
	
	nmap.set_port_state(host, port, "open")
	socket:close()

	return stdnse.format_output( true, netstat )
end

