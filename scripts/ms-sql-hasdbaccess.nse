description = [[
Queries Microsoft SQL Server (ms-sql) for a list of databases a user has
access to.

The script needs an account with the sysadmin server role to work.
It needs to be fed credentials through the script arguments or from
the scripts <code>mssql-brute</code> or <code>mssql-empty-password</code>.

When run, the script iterates over the credentials and attempts to run
the command until either all credentials are exhausted or until the
command is executed.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "discovery","safe"}

require 'shortport'
require 'stdnse'
require 'mssql'

dependencies = {"ms-sql-brute", "ms-sql-empty-password"}
---
-- @args mssql.username specifies the username to use to connect to
--       the server. This option overrides any accounts found by
--       the <code>mssql-brute</code> and <code>mssql-empty-password</code> scripts.
--
-- @args mssql.password specifies the password to use to connect to
--       the server. This option overrides any accounts found by
--       the <code>ms-sql-brute</code> and <code>ms-sql-empty-password</code> scripts.
--
-- @args ms-sql-hasdbaccess.limit limits the amount of databases per-user
--       that are returned (default 5). If set to zero or less all 
--       databases the user has access to are returned.
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-hasdbaccess:  
-- |   webshop_reader
-- |     dbname	owner
-- |     hr	sa
-- |     finance	sa
-- |     webshop	sa
-- |   lordvader
-- |     dbname	owner
-- |     testdb	CQURE-NET\Administr
-- |_    webshop	sa

-- Version 0.1
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

portrule = shortport.port_or_service(1433, "ms-sql-s")

local function table_contains( tbl, val )
	for k,v in pairs(tbl) do
		if ( v == val ) then
			return true
		end
	end
	return false
end

action = function( host, port )

	local status, result, helper, rs	
	local username = stdnse.get_script_args('mssql.username')
	local password = stdnse.get_script_args('mssql.password') or ""
	local creds
	local query, limit
	local output = {}
	local exclude_dbs = { "'master'", "'tempdb'", "'model'", "'msdb'" }
	
	local RS_LIMIT = stdnse.get_script_args( {'mssql-hasdbaccess.limit', 'ms-sql-hasdbaccess.limit' } )
		and tonumber(stdnse.get_script_args( {'mssql-hasdbaccess.limit', 'ms-sql-hasdbaccess.limit' } )) or 5
	
	if ( RS_LIMIT <= 0 ) then
		limit = ""
	else
		limit = string.format( "TOP %d", RS_LIMIT )
	end
	
	local query = { [[CREATE table #hasaccess(dbname varchar(255), owner varchar(255), 
							 DboOnly bit, ReadOnly bit, SingelUser bit, Detached bit,
							 Suspect bit, Offline bit, InLoad bit, EmergencyMode bit,
							 StandBy bit, [ShutDown] bit, InRecovery bit, NotRecovered bit )]],
							

							"INSERT INTO #hasaccess EXEC sp_MShasdbaccess",
							("SELECT %s dbname, owner FROM #hasaccess WHERE dbname NOT IN(%s)"):format(limit, stdnse.strjoin(",", exclude_dbs)),
	 						"DROP TABLE #hasaccess" }

	if ( username ) then
		creds = {}
		creds[username] = password
	elseif ( not(username) and nmap.registry.mssqlusers ) then
		-- do we have a sysadmin?
		creds = nmap.registry.mssqlusers
	end
	
	-- If we don't have valid creds, simply fail silently
	if ( not(creds) ) then
		return
	end
	
	for username, password in pairs( creds ) do
		helper = mssql.Helper:new()
 		status, result = helper:Connect(host, port)
		if ( not(status) ) then
			return "  \n\n" .. result
		end
		
		status, result = helper:Login( username, password, nil, host.ip )
		if ( not(status) ) then
			stdnse.print_debug("ERROR: %s", result)
			break
		end

		for _, q in pairs(query) do
			status, result = helper:Query( q )
			if ( status ) then
				-- Only the SELECT statement should produce output
				if ( #result.rows > 0 ) then
					rs = result
				end
			end
		end
		
		helper:Disconnect()

		if ( status and rs) then
			result = mssql.Util.FormatOutputTable( rs, true )
			result.name = username
			if ( RS_LIMIT > 0 ) then
				result.name = result.name .. (" (Showing %d first results)"):format(RS_LIMIT)
			end
			table.insert( output, result )
		end
	end	
	
	return stdnse.format_output( true, output )

end
