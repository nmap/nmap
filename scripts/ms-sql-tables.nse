description = [[
Queries Microsoft SQL Server (ms-sql) for a list of tables per database.

The sysdatabase table should be accessible by more or less everyone
The script attempts to use the sa account over any other if it has
the password in the registry. If not the first account in the
registry is used.

Once we have a list of databases we iterate over it and attempt to extract
table names. In order for this to succeed we need to have either
sysadmin privileges or an account with access to the db. So, each
database we successfully enumerate tables from we mark as finished, then
iterate over known user accounts until either we have exhausted the users
or found all tables in all the databases.

Tables installed by default are excluded.
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
--       the <code>ms-sql-brute</code> and <code>ms-sql-empty-password</code> scripts.
--
-- @args mssql.password specifies the password to use to connect to
--       the server. This option overrides any accounts found by
--       the <code>ms-sql-brute</code> and <code>ms-sql-empty-password</code> scripts.
--
-- @args ms-sql-tables.maxdb Limits the amount of databases that are
--       processed and returned (default 5). If set to zero or less 
--       all databases are processed.
--
-- @args ms-sql-tables.maxtables Limits the amount of tables returned
--       (default 5). If set to zero or less all tables are returned.
--
-- @args ms-sql-tables.keywords If set shows only tables or columns matching
--		 the keywords
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-tables:  
-- |   webshop
-- |     table	column	type	length
-- |     payments	user_id	int	4
-- |     payments	purchase_id	int	4
-- |     payments	cardholder	varchar	50
-- |     payments	cardtype	varchar	50
-- |     payments	cardno	varchar	50
-- |     payments	expiry	varchar	50
-- |     payments	cvv	varchar	4
-- |     products	id	int	4
-- |     products	manu	varchar	50
-- |     products	model	varchar	50
-- |     products	productname	varchar	100
-- |     products	price	float	8
-- |     products	imagefile	varchar	255
-- |     products	quantity	int	4
-- |     products	keywords	varchar	100
-- |     products	description	text	16
-- |     users	id	int	4
-- |     users	username	varchar	50
-- |     users	password	varchar	50
-- |_    users	fullname	varchar	100

-- Version 0.1
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 04/02/2010 - v0.2 
--		- Added support for filters
--		- Changed output formatting of restrictions
--		- Added parameter information in output if parameters are using their
--		  defaults.

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

	local status, result, dbs, tables, helper	
	local username = stdnse.get_script_args( 'mssql.username' )
	local password = stdnse.get_script_args( 'mssql.password' ) or ""
	
	local output = {}
	local exclude_dbs = { "'master'", "'tempdb'", "'model'", "'msdb'" }
	local db_query
	local done_dbs = {}
	local creds = {}
	local db_limit, tbl_limit

	local DB_COUNT = stdnse.get_script_args( {'ms-sql-tables.maxdb', 'mssql-tables.maxdb'} )
		and tonumber( stdnse.get_script_args( {'ms-sql-tables.maxdb', 'mssql-tables.maxdb'} ) ) or 5
	local TABLE_COUNT = stdnse.get_script_args( {'ms-sql-tables.maxtables', 'mssql-tables.maxtables' } )
		and tonumber( stdnse.get_script_args( {'ms-sql-tables.maxtables', 'mssql-tables.maxtables' } ) ) or 2
	local keywords_filter = ""
	
	if ( DB_COUNT <= 0 ) then
		db_limit = ""
	else
		db_limit = string.format( "TOP %d", DB_COUNT )
	end
	if (TABLE_COUNT <= 0 ) then
		tbl_limit = ""
	else
		tbl_limit = string.format( "TOP %d", TABLE_COUNT )
	end
	
	-- Build the keyword filter
	if ( nmap.registry.args['mssql-tables.keywords'] ) then
		local keywords = nmap.registry.args['mssql-tables.keywords'] 
		local tmp_tbl = {}
		
		if( type(keywords) == 'string' ) then
			keywords = { keywords }
		end
		
		for _, v in ipairs(keywords) do
			table.insert(tmp_tbl, ("'%s'"):format(v))
		end
		
		keywords_filter = (" AND ( so.name IN (%s) or sc.name IN (%s) ) "):format( 
							stdnse.strjoin(",", tmp_tbl), 
							stdnse.strjoin(",", tmp_tbl) 
							)
	end
	
	db_query = ("SELECT %s name from master..sysdatabases WHERE name NOT IN (%s)"):format(db_limit, stdnse.strjoin(",", exclude_dbs))

	if ( username ) then
		creds[username] = password
	elseif ( not(username) and nmap.registry.mssqlusers ) then
		-- do we have a sysadmin?
		if ( nmap.registry.mssqlusers.sa ) then
			creds["sa"] = nmap.registry.mssqlusers.sa
		else
			creds = nmap.registry.mssqlusers
		end
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

		status, dbs = helper:Query( db_query )

		if ( status ) then
			-- all done?
			if ( #done_dbs == #dbs.rows ) then
				break
			end

			for k, v in pairs(dbs.rows) do
				if ( not( table_contains( done_dbs, v[1] ) ) ) then
					query = [[ SELECT so.name 'table', sc.name 'column', st.name 'type', sc.length 
								FROM %s..syscolumns sc, %s..sysobjects so, %s..systypes st
								WHERE so.id = sc.id AND sc.xtype=st.xtype AND
								so.id IN (SELECT %s id FROM %s..sysobjects WHERE xtype='U') %s ORDER BY so.name, sc.name, st.name]]
					query = query:format( v[1], v[1], v[1], tbl_limit, v[1], keywords_filter)
					status, tables = helper:Query( query )
					if ( not(status) ) then
						stdnse.print_debug(tables)
					else
						local item = {}
						item = mssql.Util.FormatOutputTable( tables, true )
						if ( #item == 0 and keywords_filter ~= "" ) then
							table.insert(item, "Filter returned no matches")
						end
						item.name = v[1]
						
						table.insert(output, item)
						table.insert(done_dbs, v[1])
					end
				end
			end
		end
		helper:Disconnect()
	end	
	
	local pos = 1
	local restrict_tbl = {}
	
	if ( stdnse.get_script_args( {'ms-sql-tables.keywords', 'mssql-tables.keywords' } ) ) then
		tmp = stdnse.get_script_args( {'ms-sql-tables.keywords', 'mssql-tables.keywords' } )
		if ( type(tmp) == 'table' ) then
			tmp = stdnse.strjoin(',', tmp)
		end
		table.insert(restrict_tbl, 1, ("Filter: %s"):format(tmp))
		pos = pos + 1
	else
		table.insert(restrict_tbl, 1, "No filter (see ms-sql-tables.keywords)")
	end

	if ( DB_COUNT > 0 ) then
		local tmp = ("Output restricted to %d databases"):format(DB_COUNT)
		if ( not(stdnse.get_script_args( { 'ms-sql-tables.maxdb', 'mssql-tables.maxdb' } ) ) ) then
			tmp = tmp .. " (see ms-sql-tables.maxdb)"
		end
		table.insert(restrict_tbl, 1, tmp)
		pos = pos + 1
	end
	
	if ( TABLE_COUNT > 0 ) then
		local tmp = ("Output restricted to %d tables"):format(TABLE_COUNT)
		if ( not(stdnse.get_script_args( { 'ms-sql-tables.maxtables', 'mssql-tables.maxtables' } ) ) ) then
			tmp = tmp .. " (see ms-sql-tables.maxtables)"
		end
		table.insert(restrict_tbl, 1, tmp)
		pos = pos + 1
	end
	
	if ( 1 < pos and #output > 0) then
		restrict_tbl.name = "Restrictions"
		table.insert(output, "")
		table.insert(output, restrict_tbl)
	end
	
	output = stdnse.format_output( true, output )
		
	return output

end
