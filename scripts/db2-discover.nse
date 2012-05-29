local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to discover DB2 servers on the network by querying open ibm-db2 UDP ports (normally port 523).
]]

---
-- @usage
-- sudo nmap -sU -p 523 --script db2-discover <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 523/udp open  ibm-db2
-- | db2-discover: 
-- |   Host: EDUSRV011
-- |_  Version: IBM DB2 v9.07.0

-- Version 0.1
-- Created 08/27/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 10/10/2010 - v0.2 - add prerule, newtargets <patrik@cqure.net> 
-- Revised 10/07/2011 - v0.3 - moved broadcast support to
--                             broadcast-db2-discover.nse <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}


portrule = shortport.version_port_or_service(523, "ibm-db2", "udp",
												{"open", "open|filtered"})

--- Converts the prodrel server string to a version string
--
-- @param server_version string containing the product release
-- @return ver string containing the version information
local function parseVersion( server_version )
	local pfx = string.sub(server_version,1,3)

	if pfx == "SQL" then
		local major_version = string.sub(server_version,4,5)

		-- strip the leading 0 from the major version, for consistency with 
		-- nmap-service-probes results
		if string.sub(major_version,1,1) == "0" then
			major_version = string.sub(major_version,2)
		end
		local minor_version = string.sub(server_version,6,7)
		local hotfix = string.sub(server_version,8)
		server_version = major_version .. "." .. minor_version .. "." .. hotfix
	else
		return "Unknown version"
	end
	
	return ("IBM DB2 v%s"):format(server_version)
end

action = function(host, port)
	
	local DB2GETADDR = "DB2GETADDR\0SQL09010\0"
	local socket = nmap.new_socket()
	local result = {}
	
	socket:set_timeout(5000)

	local status, err = socket:connect( host, port, "udp")
	if ( not(status) ) then return end

	status, err = socket:send( DB2GETADDR )
	if ( not(status) ) then return end

	local data
	status, data = socket:receive()
	if( not(status) ) then
		socket:close()
		return
	end
		
	local version, srvname = data:match("DB2RETADDR.(SQL%d+).(.-)\0")

	if ( status ) then
		table.insert( result, ("Host: %s"):format(srvname) )
		table.insert( result, ("Version: %s"):format(parseVersion(version)) )
	end

	socket:close()	
	-- set port to open
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, result )	
end
