local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate Windows services through SNMP.
]]

---
-- @output
-- | snmp-win32-services:  
-- |   Apache Tomcat
-- |   Application Experience Lookup Service
-- |   Application Layer Gateway Service
-- |   Automatic Updates
-- |   COM+ Event System
-- |   COM+ System Application
-- |   Computer Browser
-- |   Cryptographic Services
-- |   DB2 - DB2COPY1 - DB2
-- |   DB2 Management Service (DB2COPY1)
-- |   DB2 Remote Command Server (DB2COPY1)
-- |   DB2DAS - DB2DAS00
-- |_  DCOM Server Process Launcher

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
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
	local snmpoid = "1.3.6.1.4.1.77.1.2.3.1.1"
	local services = {}
	local status

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, services = snmp.snmpWalk( socket, snmpoid )
	socket:close()

	if ( not(status) ) or ( services == nil ) or ( #services == 0 ) then
		return
	end
	
	services = process_answer(services)
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, services )
end

