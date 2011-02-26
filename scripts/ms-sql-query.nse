-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Runs a query against Microsoft SQL Server (ms-sql).

SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
and/or <code>mssql.username</code> & <code>mssql.password</code>)
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

NOTE: Communication with instances via named pipes depends on the <code>smb</code>
library. To communicate with (and possibly to discover) instances via named pipes,
the host must have at least one SMB port (e.g. TCP 445) that was scanned and
found to be open. Additionally, named pipe connections may require Windows
authentication to connect to the Windows host (via SMB) in addition to the
authentication required to connect to the SQL Server instances itself. See the
documentation and arguments for the <code>smb</code> library for more information.

NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
with ports that were not included in the port list for the Nmap scan. This can
be disabled using the <code>mssql.scanned-ports-only</code> script argument.
]]

---
-- @usage
-- nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password=sa,ms-sql-query.query="SELECT * FROM master..syslogins" <host>
--
-- @args ms-sql-query.query The query to run against the server.
--       (default: SELECT @@version version)
--
-- @output
-- | ms-sql-query:  
-- |   [192.168.100.25\MSSQLSERVER]
-- |     Query: SELECT @@version version
-- |       version
-- |       =======
-- |       Microsoft SQL Server 2005 - 9.00.3068.00 (Intel X86) 
-- |     	Feb 26 2008 18:15:01 
-- |     	Copyright (c) 1988-2005 Microsoft Corporation
-- |_    	Express Edition on Windows NT 5.2 (Build 3790: Service Pack 2)
--

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 - Added ability to run against all instances on a host;
--							   added compatibility with changes in mssql.lua (Chris Woodbury)

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'mssql'

dependencies = {"ms-sql-brute", "ms-sql-empty-password", "ms-sql-discover"}

hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()

--- 
local function process_instance( instance )
	local status, result	
	-- the tempdb should be a safe guess, anyway the library is set up
	-- to continue even if the DB is not accessible to the user
	local database = stdnse.get_script_args( 'mssql.database' ) or "tempdb"
	local query = stdnse.get_script_args( {'ms-sql-query.query', 'mssql-query.query' } ) or "SELECT @@version version"
	local helper = mssql.Helper:new()

	status, result = helper:ConnectEx( instance )
	
	if status then
		status, result = helper:LoginEx( instance, database )
		if ( not(status) ) then result = "ERROR: " .. result end
	end
	if status then
		status, result = helper:Query( query )
		if ( not(status) ) then result = "ERROR: " .. result end
	end
	
	helper:Disconnect()
	
	if status then
		result = mssql.Util.FormatOutputTable( result, true )
		result["name"] = string.format( "Query: %s", query )
	end
	local instanceOutput = {}
	instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
	table.insert( instanceOutput, result )
	
	return instanceOutput
end


action = function( host, port )
	local scriptOutput = {}
	local status, instanceList = mssql.Helper.GetTargetInstances( host, port )
	
	if ( not status ) then
		return stdnse.format_output( false, instanceList )
	else
		for _, instance in pairs( instanceList ) do
			local instanceOutput = process_instance( instance )
			if instanceOutput then
				table.insert( scriptOutput, instanceOutput )
			end
		end
		if ( not( stdnse.get_script_args( {'ms-sql-query.query', 'mssql-query.query' } ) ) ) then
			table.insert(scriptOutput, 1, "(Use --script-args=ms-sql-query.query='<QUERY>' to change query.)")
		end
	end
	
	return stdnse.format_output( true, scriptOutput )
end
