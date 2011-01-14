description = [[
Attempts to discover DB2 servers on the network by querying open ibm-db2 UDP ports (normally port 523).
]]

---
-- @usage
-- sudo ./nmap -sU -p 523 --script db2-discover <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 523/udp open  ibm-db2
-- | db2-discover: 
-- |   10.0.200.132 (UBU804-DB2E) - IBM DB2 v9.07.0
-- |_  10.0.200.119 (EDUSRV011) - IBM DB2 v9.07.0

-- Version 0.1
-- Created 08/27/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 10/10/2010 - v0.2 - add prerule, newtargets <patrik@cqure.net> 

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

require "stdnse"
require "shortport"
require "target"

prerule = function() return true end
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

preaction = function()

	local DB2GETADDR = "DB2GETADDR\0SQL09010\0"
	local socket = nmap.new_socket("udp")
	local result = {}
	local host, port = "255.255.255.255", 523

	socket:set_timeout(5000)
	local status = socket:sendto( host, port, DB2GETADDR )
	if ( not(status) ) then return end

	while(true) do
		local data
		status, data = socket:receive()
		if( not(status) ) then break end
		
		local version, srvname = data:match("DB2RETADDR.(SQL%d+).(.-)%z")
		local _, ip
		status, _, _, ip, _ = socket:get_info()
		if ( not(status) ) then return end
		
		if target.ALLOW_NEW_TARGETS then target.add(ip)	end

		if ( status ) then
			table.insert( result, ("%s - Host: %s; Version: %s"):format(ip, srvname, parseVersion( version ) )  )
		end
	end
	socket:close()	

	return stdnse.format_output( true, result )
end

scanaction = function(host, port)
	
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
		
	local version, srvname = data:match("DB2RETADDR.(SQL%d+).(.-)%z")

	if ( status ) then
		table.insert( result, ("Host: %s"):format(srvname) )
		table.insert( result, ("Version: %s"):format(parseVersion(version)) )
	end

	socket:close()	
	-- set port to open
	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, result )	
end


-- Function dispatch table
local actions = {
	prerule = preaction,
	hostrule = scanaction,
	portrule = scanaction,
}

function action (...) return actions[SCRIPT_TYPE](...) end
