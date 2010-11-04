description = [[
Attempts to brute-force LDAP authentication. By default
it uses the built-in username and password lists. In order to use your
own lists use the <code>userdb</code> and <code>passdb</code> script arguments.

This script does not make any attempt to prevent account lockout!
If the number of passwords in the dictionary exceed the amount of
allowed tries, accounts will be locked out. This usually happens 
very quickly.

Authenticating against Active Directory using LDAP does not use the
Windows user name but the user accounts distinguished name. LDAP on Windows
2003 allows authentication using a simple user name rather than using the
fully distinguished name. E.g., "Patrik Karlsson" vs.
"cn=Patrik Karlsson,cn=Users,dc=cqure,dc=net"
This type of authentication is not supported on e.g. OpenLDAP.

This script uses some AD-specific support and optimizations:
* LDAP on Windows 2003 reports different error messages depending on whether an account exists or not. If the script recieves an error indicating that the username does not exist it simply stops guessing passwords for this account and moves on to the next.
* The script attempts to authenticate with the username only if no LDAP base is specified. The benefit of authenticating this way is that the LDAP path of each account does not need to be known in advance as it's looked up by the server.
]]

---
-- @usage
-- nmap -p 389 --script ldap-brute --script-args \
--  ldap.base='"cn=users,dc=cqure,dc=net"' <host>
--
-- @output
-- 389/tcp open  ldap
-- | ldap-brute:  
-- |_  ldaptest:ldaptest => Login Correct
--
-- @args ldap.base If set, the script will use it as a base for the password
--       guessing attempts. If unset the user list must either contain the
--       distinguished name of each user or the server must support
--       authentication using a simple user name. See the AD discussion in the description.

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'stdnse'
require 'ldap'
require 'unpwdb'
require 'comm'

-- Version 0.3
-- Created 01/20/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/26/2010 - v0.2 - cleaned up unpwdb related code, fixed ssl stuff
-- Revised 02/17/2010 - v0.3 - added AD specific checks and fixed bugs related to LDAP base

portrule = shortport.port_or_service({389,636}, {"ldap","ldapssl"})

--- Tries to determine a valid naming context to use to validate credentials
--
-- @param socket socket already connected to LDAP server
-- @return string containing a valid naming context
function get_naming_context( socket )
	
	local req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default, attributes = { "defaultNamingContext", "namingContexts" } }
	local status, searchResEntries = ldap.searchRequest( socket, req ) 
	
	if not status then
		return nil
	end
	
	local contexts = ldap.extractAttribute( searchResEntries, "defaultNamingContext" )

	-- OpenLDAP does not have a defaultNamingContext
	if not contexts then
		contexts = ldap.extractAttribute( searchResEntries, "namingContexts" )
	end

	if contexts and #contexts > 0 then
		return contexts[1]
	end
	
	return nil
end

--- Attempts to validate the credentials by requesting the base object of the supplied context
--
-- @param socket socket already connected to the LDAP server
-- @param context string containing the context to search
-- @return true if credentials are valid and search was a success, false if not.
function is_valid_credential( socket, context )
	local req = { baseObject = context, scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default, attributes = nil }
	local status, searchResEntries = ldap.searchRequest( socket, req )				

	return status
end


action = function( host, port )

	local result, response, status, context, valid_accounts = {}, nil, nil, nil, {}	
	local usernames, passwords, username, password, fq_username
	local user_cnt, invalid_account_cnt, tot_tries = 0, 0, 0
	
	local clock_start = nmap.clock_ms()
	
	local ldap_anonymous_bind = string.char( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 )
	local socket, _, opt = comm.tryssl( host, port, ldap_anonymous_bind, nil )
	
	local base_dn = nmap.registry.args['ldap.base']
			
	if not socket then
		return
	end

	-- We close and re-open the socket so that the anonymous bind does not distract us
	socket:close()
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	status = socket:connect(host, port, opt)
	if not status then
		return
	end
	
	context = get_naming_context(socket)
	
	if not context then
		stdnse.print_debug("Failed to retrieve namingContext")
		socket:close()
		return
	end
	
 	status, usernames = unpwdb.usernames()
	if not status then
		return
	end
	
	status, passwords = unpwdb.passwords()
	if not status then
		return
	end
	
	for username in usernames do
		-- if a base DN was set append our username (CN) to the base
		if base_dn then
			fq_username = ("cn=%s,%s"):format(username, base_dn)
		else
			fq_username = username
		end
		user_cnt = user_cnt + 1
		for password in passwords do			
			tot_tries = tot_tries + 1

			-- handle special case where we want to guess the username as password
			if password == "%username%" then
				password = username
			end

			stdnse.print_debug( "Trying %s/%s ...", fq_username, password )
			status, response = ldap.bindRequest( socket, { version=3, ['username']=fq_username, ['password']=password} )

			-- if the DN (username) does not exist, break loop
			if not status and response:match("invalid DN") then
				stdnse.print_debug( "%s returned: \"Invalid DN\"", fq_username )
				invalid_account_cnt = invalid_account_cnt + 1
				break
			end
			
			-- Is AD telling us the account does not exist?
			if not status and response:match("AcceptSecurityContext error, data 525, vece") then
				invalid_account_cnt = invalid_account_cnt + 1
				break
			end

			-- Account Locked Out
			if not status and response:match("AcceptSecurityContext error, data 775, vece") then
				table.insert( valid_accounts, string.format("%s => Account locked out", fq_username ) )
				break
			end

			-- Login correct, account disabled
			if not status and response:match("AcceptSecurityContext error, data 533, vece") then
				table.insert( valid_accounts, string.format("%s:%s => Login correct, account disabled", fq_username, password:len()>0 and password or "<empty>" ) )
				break
			end

			-- Login correct, user must change password
			if not status and response:match("AcceptSecurityContext error, data 773, vece") then
				table.insert( valid_accounts, string.format("%s:%s => Login correct, user must change password", fq_username, password:len()>0 and password or "<empty>" ) )
				break
			end

			--Login, correct
			if status then
				status = is_valid_credential( socket, context )
				if status then
					table.insert( valid_accounts, string.format("%s:%s => Login correct", fq_username, password:len()>0 and password or "<empty>" ) )
					
					-- Add credentials for other ldap scripts to use
					if nmap.registry.ldapaccounts == nil then
						nmap.registry.ldapaccounts = {}
					end	
					nmap.registry.ldapaccounts[fq_username]=password
					
					break
				end
			end			
		end
		passwords("reset")
	end

	stdnse.print_debug( "Finnished brute against LDAP, total tries: %d, tps: %d", tot_tries, ( tot_tries / ( ( nmap.clock_ms() - clock_start ) / 1000 ) ) )

	if ( invalid_account_cnt == user_cnt and base_dn ~= nil ) then
		return "WARNING: All usernames were invalid. Invalid LDAP base?"
	end

	local output = stdnse.format_output(true, valid_accounts) or ""

	return output

end
