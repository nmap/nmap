description = [[
Runs a query against Microsoft SQL Server (ms-sql).
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'mssql'

dependencies = {"ms-sql-brute", "ms-sql-empty-password"}

---
-- @args ms-sql-query.query specifies the query to run against the server.
--       (default SELECT @@version version)
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-query:  
-- |   
-- |   Microsoft SQL Server 2005 - 9.00.3068.00 (Intel X86) 
-- | 	Feb 26 2008 18:15:01 
-- | 	Copyright (c) 1988-2005 Microsoft Corporation
-- |_	Express Edition on Windows NT 5.2 (Build 3790: Service Pack 2)

-- Version 0.1
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

portrule = shortport.port_or_service(1433, "ms-sql-s")

action = function( host, port )

	local status, result, helper	
	local username = stdnse.get_script_args( 'mssql.username' )
	local password = stdnse.get_script_args( 'mssql.password' ) or ""
	-- the tempdb should be a safe guess, anyway the library is set up
	-- to continue even if the DB is not accessible to the user
	local database = stdnse.get_script_args( 'mssql.database' ) or "tempdb"
	local query = stdnse.get_script_args( {'ms-sql-query.query', 'mssql-query.query' } ) or "SELECT @@version version"
	
	if ( not(username) and nmap.registry.mssqlusers ) then
		-- do we have a sysadmin?
		if ( nmap.registry.mssqlusers.sa ) then
			username = "sa"
			password = nmap.registry.mssqlusers.sa
		else
			-- ok were stuck with some n00b account, just get the first one
			for user, pass in pairs(nmap.registry.mssqlusers) do
				username = user
				password = pass
				break
			end
		end
	end
	
	-- If we don't have a valid username, simply fail silently
	if ( not(username) ) then
		return
	end
	
	helper = mssql.Helper:new()
 	status, result = helper:Connect(host, port)
	if ( not(status) ) then
		return "  \n\n" .. result
	end
		
	status, result = helper:Login( username, password, database, host.ip )
	if ( not(status) ) then
		return "  \n\nERROR: " .. result
	end

	status, result = helper:Query( query )
	helper:Disconnect()
	
	if ( not(status) ) then
		return "  \n\nERROR: " .. result
	end

	result = mssql.Util.FormatOutputTable( result, true )
	if ( not(nmap.registry.args['mssql-query.query']) ) then
		table.insert(result, 1, query)
		result = stdnse.format_output( true, result )
		result = "(Use --script-args=mssql-query.query='<QUERY>' to change query.)" .. result
	else
		result = stdnse.format_output( true, result )
	end
	
	return result

end
