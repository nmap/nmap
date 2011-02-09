description = [[
Queries Microsoft SQL Server (ms-sql) for a list of databases, linked
servers, and configuration settings.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'mssql'

dependencies = {"ms-sql-brute", "ms-sql-empty-password"}

---
-- @args mssql.username specifies the username to use to connect to
--       the server. This option overrides any accounts found by
--       the mssql-brute and mssql-empty-password scripts.
--
-- @args mssql.password specifies the password to use to connect to
--       the server. This option overrides any accounts found by
--       the mssql-brute and mssql-empty-password scripts.
--
-- @args ms-sql-config.showall if set shows all configuration options.
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-config:
-- |   Databases
-- |     name      db_size owner
-- |     ====      ======= =====
-- |     nmap            2.74 MB   MAC-MINI\david
-- |   Configuration
-- |     name      value   inuse   description
-- |     ====      =====   =====   ===========
-- |     SQL Mail XPs      0       0       Enable or disable SQL Mail XPs
-- |     Database Mail XPs 0       0       Enable or disable Database Mail XPs
-- |     SMO and DMO XPs   1       1       Enable or disable SMO and DMO XPs
-- |     Ole Automation Procedures 0       0       Enable or disable Ole Automation Procedures
-- |     xp_cmdshell       0       0       Enable or disable command shell
-- |     Ad Hoc Distributed Queries        0       0       Enable or disable Ad Hoc Distributed Queries
-- |     Replication XPs   0       0       Enable or disable Replication XPs
-- |   Linked Servers
-- |     srvname   srvproduct      providername
-- |     =======   ==========      ============
-- |_    MAC-MINI  SQL Server      SQLOLEDB

-- Version 0.1
-- Created 04/02/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

portrule = shortport.port_or_service(1433, "ms-sql-s")

action = function( host, port )

	local status, helper, response	
	local username = stdnse.get_script_args( 'mssql.username' )
	local password = stdnse.get_script_args( 'mssql.password' ) or ""
	local result, result_part = {}, {}
	local conf_filter = stdnse.get_script_args( {'mssql-config.showall', 'ms-sql-config.showall'} ) and "" 
		or " WHERE configuration_id > 16384"
	local db_filter = stdnse.get_script_args( {'mssql-config.showall', 'ms-sql-config.showall'} ) and "" 
		or " WHERE name NOT IN ('master','model','tempdb','msdb')"
	
	local queries = { 
		[2]={ ["Configuration"] = [[ SELECT name, 
								cast(value as varchar) value, 
								cast(value_in_use as varchar) inuse, 
								description 
								FROM sys.configurations ]] .. conf_filter }, 
		[3]={ ["Linked Servers"] = [[ SELECT srvname, srvproduct, providername 
									FROM master..sysservers 
									WHERE srvid > 0 ]] },
		[1]={ ["Databases"] = [[ CREATE TABLE #nmap_dbs(name varchar(255), db_size varchar(255), owner varchar(255), 
									dbid int, created datetime, status varchar(512), compatibility_level int )
								INSERT INTO #nmap_dbs EXEC sp_helpdb
								SELECT name, db_size, owner 
									FROM #nmap_dbs ]] .. db_filter .. [[
								DROP DATABASE #nmap_dbs ]] }
	}
	
	if ( not(username) and nmap.registry.mssqlusers ) then
		-- do we have a sysadmin?
		if ( nmap.registry.mssqlusers.sa ) then
			username = "sa"
			password = nmap.registry.mssqlusers.sa
		else
			-- ok were stuck with some non sysadmin account, just get the first one
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
 	status, response = helper:Connect(host, port)
	if ( not(status) ) then
		return "  \n\n" .. response
	end
		
	status, response = helper:Login( username, password, nil, host.ip )
	if ( not(status) ) then
		return "  \n\nERROR: " .. response
	end

	for _, v in ipairs( queries ) do
		for header, query in pairs(v) do
			status, result_part = helper:Query( query )

			if ( not(status) ) then
				return "  \n\nERROR: " .. result_part
			end
			result_part = mssql.Util.FormatOutputTable( result_part, true )
			result_part.name = header
			table.insert( result, result_part )
		end
	end
	
	helper:Disconnect()
	
	return stdnse.format_output( true, result )

end
