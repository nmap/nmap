description = [[
Attempts to extract information from IBM DB2 Server instances.  The script sends a
DB2 EXCSAT (exchange server attributes) command packet and parses the response.
]]

---
-- @output
-- PORT      STATE SERVICE
-- 50000/tcp open  ibm-db2
-- |  db2-info: DB2 Version: 8.02.9
-- |  Server Platform: QDB2/SUN
-- |  Instance Name:   db2inst1
-- |_ External Name:   db2inst1db2agent00002B430
  
author = "Patrik Karlsson"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "version"}

require "stdnse"
require "shortport"
require "db2"

-- Version 0.1
-- Created 05/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

--
-- parseVersion was ripped from the old db2-info.nse written by Tom Sellers
--

portrule = shortport.port_or_service({50000,60000},"ibm-db2", "tcp", {"open", "open|filtered"})

--- Converts the prodrel server string to a version string
--
-- @param server_version string containing the product release
-- @return ver string containing the version information
local function parseVersion( server_version )
	
	if string.sub(server_version,1,3) == "SQL" then
		local major_version = string.sub(server_version,4,5)

		-- strip the leading 0 from the major version, for consistency with 
		-- nmap-service-probes results
		if string.sub(major_version,1,1) == "0" then
			major_version = string.sub(major_version,2)
		end
		local minor_version = string.sub(server_version,6,7)
		local hotfix = string.sub(server_version,8)
		server_version = major_version .. "." .. minor_version .. "." .. hotfix
	end
	
	return server_version
end

action = function( host, port )

	local db2helper = db2.Helper:new()
	local status, response
	
	status, response = db2helper:connect(host, port)
	if( not(status) ) then
		return response
	end

	status, response = db2helper:getServerInfo()
	if( not(status) ) then
		return response
	end
	
	db2helper:close()
	
	-- Set port information
	port.version.name = "ibm-db2"
	port.version.product = "IBM DB2 Database Server"
	port.version.name_confidence = 100
	nmap.set_port_state(host, port, "open")
	if response.srvclass ~= nil then port.version.extrainfo = response.srvclass   end
	
	nmap.set_port_version(host, port, "hardmatched")
	
	-- Generate results
	    local results = "DB2 Version: " .. parseVersion(response.prodrel) .. "\n"
	results = results .. "Server Platform: " .. response.srvclass .. "\n"
	results = results .. "Instance Name:   " .. response.srvname .. "\n"
	results = results .. "External Name:   " .. response.extname
	
	return results
end