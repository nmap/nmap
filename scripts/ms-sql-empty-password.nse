description = [[
Attempts to authenticate using an empty password for the sysadmin (sa) account.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth","intrusive"}

require 'shortport'
require 'stdnse'
require 'mssql'

---
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-empty-password:  
-- |_  sa:<empty> => Login Correct
--
--

-- Version 0.1
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

portrule = shortport.port_or_service(1433, "ms-sql-s")

action = function( host, port )

	local helper, status, result
	local username, password, database, valid_accounts = "sa", "", "tempdb", {}
	
	helper = mssql.Helper:new()
	status, result = helper:Connect(host, port)
		
	if( not(status) ) then
		return "  \n\n" .. result
	end
			
	status, result = helper:Login( username, password, database, host.ip )
	helper:Disconnect()
			
	if status then
		nmap.registry.mssqlusers = nmap.registry.mssqlusers or {}	
		nmap.registry.mssqlusers[username]=password
				
		table.insert( valid_accounts, string.format("%s:%s => Login Success", username, password:len()>0 and password or "<empty>" ) )
	end
			
	return stdnse.format_output(true, valid_accounts)	

end
