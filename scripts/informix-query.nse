local informix = require "informix"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Runs a query against IBM Informix Dynamic Server using the given
authentication credentials (see also: informix-brute).
]]

---
-- @usage
-- nmap -p 9088 <host> --script informix-query --script-args informix-query.username=informix,informix-query.password=informix
--
-- @output
-- PORT     STATE SERVICE
-- 9088/tcp open  unknown syn-ack
-- | informix-query:  
-- |   Information
-- |     User: informix
-- |     Database: sysmaster
-- |     Query: "SELECT FIRST 1 DBINFO('dbhostname') hostname, DBINFO('version','full') version FROM systables"
-- |   Results
-- |     hostname      version                                        
-- |_    patrik-laptop IBM Informix Dynamic Server Version 11.50.UC4E 
--
-- @args informix-query.username The username used for authentication
-- @args informix-query.password The password used for authentication
-- @args informix-query.database The name of the database to connect to
--       (default: sysmaster)
-- @args informix-query.query The query to run against the server
--       (default: returns hostname and version)
-- @args informix-query.instance The name of the instance to connect to

-- Version 0.1

-- Created 07/28/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}
dependencies = { "informix-brute" }


portrule = shortport.port_or_service( { 1526, 9088, 9090, 9092 }, "informix", "tcp", "open") 

action = function( host, port )
	local instance = stdnse.get_script_args('informix-info.instance')
	local helper
	local status, data
	local result = {}
	local user = stdnse.get_script_args('informix-query.username')
	local pass = stdnse.get_script_args('informix-query.password')
	local query = stdnse.get_script_args('informix-query.query')
	local db = stdnse.get_script_args('informix-query.database') or "sysmaster"
	
	query = query or "SELECT FIRST 1 DBINFO('dbhostname') hostname, " ..
					 "DBINFO('version','full') version FROM systables"

	helper = informix.Helper:new( host, port, instance )
	
	-- If no user was specified lookup the first user in the registry saved by
	-- the informix-brute script
	if ( not(user) ) then
		if ( nmap.registry['informix-brute'] and nmap.registry['informix-brute'][1]["username"] ) then
			user = nmap.registry['informix-brute'][1]["username"]
			pass = nmap.registry['informix-brute'][1]["password"]
		else
			return "  \n  ERROR: No credentials specified (see informix-table.username and informix-table.password)"
		end
	end
	
	status, data = helper:Connect()
	if ( not(status) ) then
		return stdnse.format_output(status, data)
	end

	status, data = helper:Login(user, pass, nil, db)
	if ( not(status) ) then	return stdnse.format_output(status, data) end

	status, data = helper:Query(query)
	if ( not(status) ) then	return stdnse.format_output(status, data) end
	
	for _, rs in ipairs(data) do
		table.insert( result, { "User: " .. user, "Database: " .. db, ( "Query: \"%s\"" ):format( rs.query ), name="Information" } )
		local tmp = informix.Util.formatTable( rs )
		tmp.name = "Results"
		table.insert(  result, tmp  )
	end
	
	
	return stdnse.format_output(status, result)
end
