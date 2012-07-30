local drda = require "drda"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to extract information from database servers supporting the DRDA
protocol. The script sends a DRDA EXCSAT (exchange server attributes)
command packet and parses the response.
]]

---
-- @output
-- PORT      STATE SERVICE
-- 50000/tcp open  drda
-- |  drda-info: DB2 Version: 8.02.9
-- |  Server Platform: QDB2/SUN
-- |  Instance Name:   db2inst1
-- |_ External Name:   db2inst1db2agent00002B430
  
author = "Patrik Karlsson"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "version"}


-- Version 0.1
-- Created 05/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

--
-- parseVersion was ripped from the old db2-info.nse written by Tom Sellers
--

portrule = shortport.version_port_or_service({50000,60000,9090,1526,1527},
                                            {"drda","ibm-db2"}, "tcp",
                                            {"open", "open|filtered"})

--- Converts the prodrel server string to a version string
--
-- @param server_version string containing the product release
-- @return ver string containing the version information
local function parseVersion( server_version )
	local pfx = string.sub(server_version,1,3)

	if pfx == "SQL" or pfx == "IFX" then
		local major_version = string.sub(server_version,4,5)

		-- strip the leading 0 from the major version, for consistency with 
		-- nmap-service-probes results
		if string.sub(major_version,1,1) == "0" then
			major_version = string.sub(major_version,2)
		end
		local minor_version = string.sub(server_version,6,7)
		local hotfix = string.sub(server_version,8)
		server_version = major_version .. "." .. minor_version .. "." .. hotfix
	elseif( pfx == "CSS" ) then
		return server_version:match("%w+/(.*)")
	end
	
	return server_version
end

action = function( host, port )

	local helper = drda.Helper:new()
	local status, response
	local results = {}
	
	status, response = helper:connect(host, port)
	if( not(status) ) then
		return response
	end

	status, response = helper:getServerInfo()
	if( not(status) ) then
		return response
	end
	
	helper:close()

	-- Set port information
	if ( response.srvclass and response.srvclass:match("IDS/") ) then
		port.version.name = "drda"
		port.version.product = "IBM Informix Dynamic Server"
		port.version.name_confidence = 100
		table.insert( results, ("Informix Version: %s"):format( parseVersion(response.prodrel) ) )
	elseif ( response.srvclass and response.srvclass:match("Apache Derby") ) then
		port.version.name = "drda"
		port.version.product = "Apache Derby Server"
		port.version.name_confidence = 100
		table.insert( results, ("Derby Version: %s"):format( parseVersion(response.prodrel) ) )
	elseif ( response.srvclass and response.srvclass:match("DB2") ) then
		port.version.name = "drda"
		port.version.product = "IBM DB2 Database Server"
		port.version.name_confidence = 100
		table.insert( results, ("DB2 Version: %s"):format( parseVersion(response.prodrel) ) )
	else
		table.insert( results, ("Version: %s"):format( response.prodrel ) )
	end
	nmap.set_port_state(host, port, "open")
	if response.srvclass ~= nil then port.version.extrainfo = response.srvclass   end
	
	nmap.set_port_version(host, port)
	
	-- Generate results
	table.insert( results, ("Server Platform: %s"):format( response.srvclass ) )
	table.insert( results, ("Instance Name: %s"):format( response.srvname ) )
	table.insert( results, ("External Name: %s"):format( response.extname ) )
	
	return stdnse.format_output( true, results )
end
