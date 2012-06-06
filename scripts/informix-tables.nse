local informix = require "informix"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves a list of tables and column definitions for each database on an Informix server.
]]

---
-- @usage
-- nmap -p 9088 <host> --script informix-tables --script-args informix-tables.username=informix,informix-tables.password=informix
--
-- @output
-- PORT     STATE SERVICE REASON
-- 9088/tcp open  unknown syn-ack
-- | informix-tables:  
-- |   Information
-- |     User: informix
-- |     Database: stores_demo
-- |   Results
-- |     table                column               rows                 
-- |     call_type            call_code            5                    
-- |     call_type            code_descr           5                    
-- |     catalog              cat_advert           74                   
-- |     catalog              cat_descr            74                   
-- |     catalog              cat_picture          74                   
-- |     catalog              catalog_num          74                   
-- |     catalog              manu_code            74                   
-- |     catalog              stock_num            74                   
-- |     classes              class                4                    
-- |     classes              classid              4                    
-- |     classes              subject              4
-- |     cust_calls          call_code           7                   
-- |     cust_calls          call_descr          7                   
-- |     cust_calls          call_dtime          7                   
-- |     cust_calls          customer_num        7                   
-- |     cust_calls          res_descr           7                   
-- |     cust_calls          res_dtime           7                   
-- |     cust_calls          user_id             7                   
-- |     warehouses          warehouse_id        4                   
-- |     warehouses          warehouse_name      4                   
-- |_    warehouses          warehouse_spec      4
--
-- @args informix-query.username The username used for authentication
-- @args informix-query.password The password used for authentication
--
-- Version 0.1
-- Created 27/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}
dependencies = { "informix-brute" }


portrule = shortport.port_or_service( { 1526, 9088, 9090, 9092 }, "informix", "tcp", "open") 

action = function( host, port )
	local helper
	local status, data
	local result, output = {}, {}
	local user = stdnse.get_script_args('informix-tables.username')
	local pass = stdnse.get_script_args('informix-tables.password') or ""
	local query= [[
		SELECT cast(tabname as char(20)) table, cast(colname as char(20)) column, cast( cast(nrows as int) as char(20)) rows
		FROM "informix".systables st, "informix".syscolumns sc 
		WHERE sc.tabid = st.tabid and st.tabid > 99 and st.tabtype='T' 
		ORDER BY table, column]]
	local excluded_dbs = { ["sysmaster"] = true, ["sysutils"] = true, ["sysuser"] = true, ["sysadmin"] = true }
	
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
	
	helper = informix.Helper:new( host, port )
	
	status, data = helper:Connect()
	if ( not(status) ) then
		return stdnse.format_output(status, data)
	end

	status, data = helper:Login(user, pass)
	if ( not(status) ) then	return stdnse.format_output(status, data) end

  local databases
	status, databases = helper:GetDatabases()
	if ( not(status) ) then
		return "  \n  ERROR: Failed to retrieve a list of databases"
	end
	
	for _, db in ipairs(databases) do
		if ( not( excluded_dbs[db] ) ) then
			status, data = helper:OpenDatabase(db)
			if ( not(status) ) then	return stdnse.format_output(status, data) end
			status, data = helper:Query( query )
			if ( not(status) ) then	return stdnse.format_output(status, data) end
						
			if ( status ) then
				data = informix.Util.formatTable( data[1] )
				data.name = "Results"
				table.insert( result, { "User: " .. user, "Database: " .. db, name="Information" } )
				table.insert(result, data )
			end
			break
		end
	end

	helper:Close()

	return stdnse.format_output( true, result )
end
