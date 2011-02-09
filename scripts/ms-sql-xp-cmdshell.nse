description = [[
Attempts to run a command using the command shell of Microsoft SQL
Server (ms-sql).

The script needs an account with the sysadmin server role to work.
It needs to be fed credentials through the script arguments or from
the scripts <code>ms-sql-brute</code> or
<code>ms-sql-empty-password</code>.

When run, the script iterates over the credentials and attempts to run
the command until either all credentials are exhausted or until the
command is executed.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}

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
-- @args mssql-xp-cmdshell.cmd specifies the OS command to run.
--       (default is ipconfig /all)
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-xp-cmdshell:  
-- |   Command: ipconfig /all; User: sa
-- |   output
-- |   
-- |   Windows IP Configuration
-- |   
-- |      Host Name . . . . . . . . . . . . : EDUSRV011
-- |      Primary Dns Suffix  . . . . . . . : cqure.net
-- |      Node Type . . . . . . . . . . . . : Unknown
-- |      IP Routing Enabled. . . . . . . . : No
-- |      WINS Proxy Enabled. . . . . . . . : No
-- |      DNS Suffix Search List. . . . . . : cqure.net
-- |   
-- |   Ethernet adapter Local Area Connection 3:
-- |   
-- |      Connection-specific DNS Suffix  . : 
-- |      Description . . . . . . . . . . . : AMD PCNET Family PCI Ethernet Adapter #2
-- |      Physical Address. . . . . . . . . : 08-00-DE-AD-C0-DE
-- |      DHCP Enabled. . . . . . . . . . . : Yes
-- |      Autoconfiguration Enabled . . . . : Yes
-- |      IP Address. . . . . . . . . . . . : 192.168.56.3
-- |      Subnet Mask . . . . . . . . . . . : 255.255.255.0
-- |      Default Gateway . . . . . . . . . : 
-- |      DHCP Server . . . . . . . . . . . : 192.168.56.2
-- |      Lease Obtained. . . . . . . . . . : den 21 mars 2010 00:12:10
-- |      Lease Expires . . . . . . . . . . : den 21 mars 2010 01:12:10
-- |_

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

	local status, result, helper	
	local username = nmap.registry.args['mssql.username']
	local password = nmap.registry.args['mssql.password'] or ""
	local creds
	local query
	local cmd = nmap.registry.args['ms-sql-xp-cmdshell.cmd'] or 'ipconfig /all'
	local output = {}

	query = ("EXEC master..xp_cmdshell '%s'"):format(cmd)

	if ( username ) then
		creds = {}
		creds[username] = password
	elseif ( not(username) and nmap.registry.mssqlusers ) then
		-- do we have a sysadmin?
		creds = {}
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

		status, result = helper:Query( query )
		helper:Disconnect()

		if ( status ) then
			output = mssql.Util.FormatOutputTable( result, true )
			if ( not(nmap.registry.args['mssql-xp-cmdshell.cmd']) ) then
				table.insert(output, 1, cmd)
				output = stdnse.format_output( true, output )
				output = "(Use --script-args=mssql-xp-cmdshell.cmd='<CMD>' to change command.)" .. output
			else
				output = stdnse.format_output( true, output )
			end

			break
		elseif ( result:gmatch("xp_configure") ) then
			if( nmap.verbosity() > 1 ) then
				return "  \nProcedure xp_cmdshell disabled, for more information see \"Surface Area Configuration\" in Books Online."
			end
		end
	end	
	
	return output

end
