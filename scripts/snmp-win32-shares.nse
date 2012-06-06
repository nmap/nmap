local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate Windows Shares through SNMP.
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

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occure if a mib did not exist
-- Revised 04/11/2010 - v0.3 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

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
	local status

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, shares = snmp.snmpWalk( socket, snmpoid )
	socket:close()

	if (not(status)) or ( shares == nil ) or ( #shares == 0 ) then
		return shares
	end
		
	shares = process_answer( shares )

	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, shares )
end

