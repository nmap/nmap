description = [[
Performs password guessing against MySQL
]]

---
-- @output
-- 3306/tcp open  mysql
-- | mysql-brute:  
-- |   root:<empty> => Login Correct
-- |_  test:test => Login Correct

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'stdnse'
require 'mysql'
require 'unpwdb'
require 'openssl'

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/23/2010 - v0.2 - revised by Patrik Karlsson, changed username, password loop, added credential storage for other mysql scripts, added timelimit
-- Revised 01/23/2010 - v0.3 - revised by Patrik Karlsson, fixed bug showing account passwords detected twice

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local result, response, status = {}, nil, nil
	local valid_accounts = {}	
	local usernames, passwords
	local username, password

	-- set a reasonable timeout value
	socket:set_timeout(5000)
		
 	usernames = try(unpwdb.usernames())
	passwords = try(unpwdb.passwords())	
	
	for username in usernames do
		for password in passwords do
				
			try( socket:connect(host, port) )	
			response = try( mysql.receiveGreeting( socket ) )

			stdnse.print_debug( "Trying %s/%s ...", username, password )

			status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )
			socket:close()

			if status then				
				-- Add credentials for other mysql scripts to use
				if nmap.registry.mysqlusers == nil then
					nmap.registry.mysqlusers = {}
				end	
				nmap.registry.mysqlusers[username]=password
				
				table.insert( valid_accounts, string.format("%s:%s => Login Correct", username, password:len()>0 and password or "<empty>" ) )
				break
			end
			
		end
		passwords("reset")
	end

	local output = stdnse.format_output(true, valid_accounts)	

	return output

end
