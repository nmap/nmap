-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Attempts to authenticate to Microsoft SQL Servers using an empty password for
the sysadmin (sa) account.

SQL Server credentials required: No (will not benefit from 
<code>mssql.username</code> & <code>mssql.password</code>).
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

WARNING: SQL Server 2005 and later versions include support for account lockout
policies (which are enforced on a per-user basis).

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
-- nmap -p 445 --script ms-sql-empty-password --script-args mssql.instance-all <host>
-- nmap -p 1433 --script ms-sql-empty-password <host>
--
-- @output
-- | ms-sql-empty-password:
-- |   [192.168.100.128\PROD]
-- |_    sa:<empty> => Login Success
--

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 (Chris Woodbury)
--		- Added ability to run against all instances on a host;
--		- Added storage of credentials on a per-instance basis
--		- Added compatibility with changes in mssql.lua

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth","intrusive"}

dependencies = {"ms-sql-discover"}

require 'shortport'
require 'stdnse'
require 'mssql'

hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()

local function test_credentials( instance, helper, username, password )
	local database = "tempdb"
	
	local status, result = helper:ConnectEx( instance )
	local loginErrorCode
	if( status ) then
		stdnse.print_debug( 2, "%s: Attempting login to %s", SCRIPT_NAME, instance:GetName() )
		status, result, loginErrorCode = helper:Login( username, password, database, instance.host.ip )
	end
	helper:Disconnect()
	
	local passwordIsGood, canLogin
	if status then
		passwordIsGood = true
		canLogin = true
	elseif ( loginErrorCode ) then
		if ( loginErrorCode == mssql.LoginErrorType.PasswordExpired ) then passwordIsGood = true end
		if ( loginErrorCode == mssql.LoginErrorType.PasswordMustChange ) then passwordIsGood = true end
		if ( loginErrorCode == mssql.LoginErrorType.AccountLockedOut ) then
			stdnse.print_debug( 1, "%s: Account %s locked out on %s", SCRIPT_NAME, username, instance:GetName() )
			table.insert( instance.ms_sql_empty, string.format("'sa' account is locked out.", result ) )
		end
		if ( mssql.LoginErrorMessage[ loginErrorCode ] == nil ) then
			stdnse.print_debug( 2, "%s: Attemping login to %s: Unknown login error number: %s",
				SCRIPT_NAME, instance:GetName(), loginErrorCode )
			table.insert( instance.ms_sql_empty, string.format( "Unknown login error number: %s", loginErrorCode ) )
		end
	else
		table.insert( instance.ms_sql_empty, string.format("Network error. Error: %s", result ) )
	end
	
	if ( passwordIsGood ) then
		local loginResultMessage = "Login Success"
		if loginErrorCode then
			loginResultMessage = mssql.LoginErrorMessage[ errorCode ] or "unknown error"
		end
		table.insert( instance.ms_sql_empty, string.format( "%s:%s => %s", username, password:len()>0 and password or "<empty>", loginResultMessage ) )
		
		-- Add credentials for other ms-sql scripts to use but don't
		-- add accounts that need to change passwords
		if ( canLogin ) then
			instance.credentials[ username ] = password
			-- Legacy storage method (does not distinguish between instances)
			nmap.registry.mssqlusers = nmap.registry.mssqlusers or {}	
			nmap.registry.mssqlusers[username]=password
		end
	end
end

--- Processes a single instance, attempting to detect an empty password for "sa"
local function process_instance( instance )

	-- One of this script's features is that it will report an instance's
	-- in both the port-script results and the host-script results. In order to
	-- avoid redundant login attempts on an instance, we will just make the
	-- attempt once and then re-use the results. We'll use a mutex to make sure
	-- that multiple script instances (e.g. a host-script and a port-script)
	-- working on the same SQL Server instance can only enter this block one at
	-- a time. 
	local mutex = nmap.mutex( instance )
	mutex( "lock" )
	
	local status, result
	
	-- If this instance has already been tested (e.g. if we got to it by both the
	-- hostrule and the portrule), don't test it again. This will reduce the risk
	-- of locking out accounts.
	if ( instance.tested_empty ~= true ) then
		instance.tested_empty = true
		
		instance.credentials = instance.credentials or {}
		instance.ms_sql_empty = instance.ms_sql_empty or {}
		
		if not instance:HasNetworkProtocols() then
			stdnse.print_debug( 1, "%s: %s has no network protocols enabled.", SCRIPT_NAME, instance:GetName() )
			table.insert( instance.ms_sql_empty, "No network protocols enabled." )
		end
		
		local helper = mssql.Helper:new()
		test_credentials( instance, helper, "sa", "" )
	end
	
	-- The password testing has been finished. Unlock the mutex.
	mutex( "done" )
	
	local instanceOutput
	if ( instance.ms_sql_empty ) then
		instanceOutput = {}
		instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
		for _, message in ipairs( instance.ms_sql_empty ) do
			table.insert( instanceOutput, message )
		end
		if ( nmap.verbosity() > 1 and table.getn( instance.ms_sql_empty ) == 0 ) then
			table.insert( instanceOutput, "'sa' account password is not blank." )
		end
	end
	
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
	end

	return stdnse.format_output( true, scriptOutput )
end
