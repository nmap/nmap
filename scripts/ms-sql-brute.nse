description = [[
Performs password guessing against Microsoft SQL Server (ms-sql).
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

require 'shortport'
require 'stdnse'
require 'mssql'
require 'unpwdb'

---
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-brute:  
-- |   webshop_reader:secret => Login Success
-- |   testuser:secret1234 => Must change password at next logon
-- |_  lordvader:secret1234 => Login Success

-- Version 0.1
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

portrule = shortport.port_or_service(1433, "ms-sql-s")

action = function( host, port )

	local result, response, status = {}, nil, nil
	local valid_accounts = {}	
	local usernames, passwords
	local username, password
	local helper = mssql.Helper:new()
	
 	status, usernames = unpwdb.usernames()
	if ( not(status) ) then
		return "  \n\nFailed to load usernames.lst"
	end
	status, passwords = unpwdb.passwords()
	if ( not(status) ) then
		return "  \n\nFailed to load usernames.lst"
	end
		
	for username in usernames do
		for password in passwords do
	
			status, result = helper:Connect(host, port)
			if( not(status) ) then
				return "  \n\n" .. result
			end
			
			stdnse.print_debug( "Trying %s/%s ...", username, password )
			status, result = helper:Login( username, password, "tempdb", host.ip )			
			helper:Disconnect()
			
			if ( status ) or ( "Must change password at next logon" == result ) then				
				-- Add credentials for other mysql scripts to use
				table.insert( valid_accounts, string.format("%s:%s => %s", username, password:len()>0 and password or "<empty>", result ) )
				-- don't add accounts that need to change passwords to the registry
				if ( result ~= "Login Success") then
					break
				end
				if nmap.registry.mssqlusers == nil then
					nmap.registry.mssqlusers = {}
				end	
				nmap.registry.mssqlusers[username]=password
				
				break
			end
			
		end
		passwords("reset")
	end

	local output = stdnse.format_output(true, valid_accounts)	

	return output
end
