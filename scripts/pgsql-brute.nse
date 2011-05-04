description = [[
Performs password guessing against PostgreSQL.
]]

---
-- @usage 
-- nmap -p 5432 --script pgsql-brute <host>
--
-- @output
-- 5432/tcp open  pgsql
-- | pgsql-brute:  
-- |   root:<empty> => Login Correct
-- |_  test:test => Login Correct
--
-- @args pgsql.nossl If set to <code>1</code> or <code>true</code>, disables SSL.
-- @args pgsql.version Force protocol version 2 or 3.

-- SSL Encryption
-- --------------
-- We need to handle several cases of SSL support
--  o SSL can be supported on a server level
--  o SSL can be enforced per host or network level
--  o SSL can be denied per host or network level

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'stdnse'
require 'unpwdb'
require 'openssl'

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/20/2010 - v0.2 - moved version detection to pgsql library 
-- Revised 03/04/2010 - v0.3 - added code from ssh-hostkey.nse to check for SSL support
--                           - added support for trusted authentication method

portrule = shortport.port_or_service(5432, "postgresql")

--- Connect a socket to the server with or without SSL
--
-- @param host table as received by the action function
-- @param port table as received by the action function
-- @param ssl boolean, if true connect using SSL
-- @return socket connected to server
local function connectSocket(host, port, ssl)
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	socket:connect(host, port)

	-- let's be responsible and avoid sending communication in the clear
	if ( ssl ) then
		status = pgsql.requestSSL(socket)
		if ( status ) then
			socket:reconnect_ssl()
		end
	end
	return socket
end

action = function( host, port )

	local status, response, ssl_enable, output
	local result, response, status, nossl = {}, nil, nil, false
	local valid_accounts = {}
	local pg
	
	if ( nmap.registry.args['pgsql.version'] ) then
		if ( tonumber(nmap.registry.args['pgsql.version']) == 2 ) then
			pg = pgsql.v2
		elseif ( tonumber(nmap.registry.args['pgsql.version']) == 3 ) then
			pg = pgsql.v3
		else
			stdnse.print_debug("pgsql-brute: Unsupported version %s", nmap.registry.args['pgsql.version'])
			return
		end
	else
		pg = pgsql.detectVersion(host, port )
	end
	
 	status, usernames = unpwdb.usernames()
	if ( not(status) ) then	return end

	status, passwords = unpwdb.passwords()
	if ( not(status) ) then	return end
	
	-- If the user explicitly does not disable SSL, enforce it
	if ( ( nmap.registry.args['pgsql.nossl'] == 'true' ) or 
		 ( nmap.registry.args['pgsql.nossl'] == '1' ) ) then
		nossl = true
	end
	
	for username in usernames do
		ssl_enable = not(nossl)
		for password in passwords do
			stdnse.print_debug( string.format("Trying %s/%s ...", username, password ) )
			socket = connectSocket( host, port, ssl_enable )
			status, response = pg.sendStartup(socket, username, username)
			
			-- if nossl is enforced by the user, we're done
			if ( not(status) and nossl ) then
				break
			end
			
			-- SSL failed, this can occure due to:
			-- 1. The server does not do SSL
			-- 2. SSL was denied on a per host or network level
			--
			-- Attempt SSL connection
			if ( not(status) ) then
				socket:close()
				ssl_enable = false
				socket = connectSocket( host, port, ssl_enable )
				status, response = pg.sendStartup(socket, username, username)
				if (not(status)) then
					if ( response:match("no pg_hba.conf entry for host") ) then
						stdnse.print_debug("The host was denied access to db \"%s\" as user \"%s\", aborting ...", username, username )
						break
					else
						stdnse.print_debug("pgsql-brute: sendStartup returned: %s", response )
						break
					end
				end
			end
	
			-- Do not attempt to authenticate if authentication type is trusted
			if ( response.authtype ~= pgsql.AuthenticationType.Success ) then
				status, response = pg.loginRequest( socket, response, username, password, response.salt)
			end
			
			if status then				
				-- Add credentials for other pgsql scripts to use
				if nmap.registry.pgsqlusers == nil then
					nmap.registry.pgsqlusers = {}
				end	
				nmap.registry.pgsqlusers[username]=password
				if ( response.authtype ~= pgsql.AuthenticationType.Success ) then
					table.insert( valid_accounts, string.format("%s:%s => Login Correct", username, password:len()>0 and password or "<empty>" ) )
				else
					table.insert( valid_accounts, string.format("%s => Trusted authentication", username ) )
				end
				break
			end
			socket:close()
		end
		passwords("reset")
	end
	
	output = stdnse.format_output(true, valid_accounts)	
	
	return output
	
end
