local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate Windows user accounts through SNMP
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
categories = {"default", "auth", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occure if a mib did not exist
-- Revised 04/11/2010 - v0.3 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

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
	local status

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, users = snmp.snmpWalk( socket, snmpoid )
	socket:close()

	if( not(status) ) then
		return
	end
	
	users = process_answer( users )

	if ( users == nil ) or ( #users == 0 ) then
		return
	end
	
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, users )
end

