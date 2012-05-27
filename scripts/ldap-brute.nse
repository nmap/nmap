local comm = require "comm"
local creds = require "creds"
local ldap = require "ldap"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

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
* LDAP on Windows 2003/2008 reports different error messages depending on whether an account exists or not. If the script receives an error indicating that the username does not exist it simply stops guessing passwords for this account and moves on to the next.
* The script attempts to authenticate with the username only if no LDAP base is specified. The benefit of authenticating this way is that the LDAP path of each account does not need to be known in advance as it's looked up by the server.  This technique will only find a match if the account Display Name matches the username being attempted.
]]

---
-- @usage
-- nmap -p 389 --script ldap-brute --script-args \
--  ldap.base='"cn=users,dc=cqure,dc=net"' <host>
--
-- @output
-- 389/tcp open  ldap
-- | ldap-brute:  
-- |_  ldaptest:ldaptest => Valid credentials
-- |   restrict.ws:restricted1 => Valid credentials, account cannot log in from current host
-- |   restrict.time:restricted1 => Valid credentials, account cannot log in at current time
-- |   valid.user:valid1 => Valid credentials
-- |   expired.user:expired1 => Valid credentials, account expired
-- |   disabled.user:disabled1 => Valid credentials, account disabled
-- |_  must.change:need2change => Valid credentials, password must be changed at next logon
--
-- @args ldap.base If set, the script will use it as a base for the password
--       guessing attempts. If both ldap.base and ldap.upnsuffix are unset the user 
--       list must either contain the distinguished name of each user or the server
--       must support authentication using a simple user name. See the AD discussion 
--       in the description.  DO NOT use ldap.upnsuffix in conjunction with ldap.base 
--       as attempts to login will fail.
--
-- @args ldap.upnsuffix  If set, the script will append this suffix value to the username 
--       to create a User Principle Name (UPN).  For example if the ldap.upnsuffix value were
--       'mycompany.com' and the username being tested was 'pete' then this script would 
--       attempt to login as 'pete@mycompany.com'.  This setting should only have value
--       when running the script against a Microsoft Active Directory LDAP implementation.
--       When the UPN is known using this setting should provide more reliable results
--       against domains that have been organized into various OUs or child domains.
--       If both ldap.base and ldap.upnsuffix are unset the user list must either contain
--       the distinguished name of each user or the server must support authentication 
--       using a simple user name. See the AD discussion in the description.
--       DO NOT use ldap.upnsuffix in conjunction with ldap.base as attempts to login
--       will fail.
--
-- @args ldap.saveprefix  If set, the script will save the output to a file
--       beginning with the specified path and name.  The file suffix will automatically
--       be added based on the output type selected.
--
-- @args ldap.savetype  If set, the script will save the passwords in the specified
--       format.  The current formats are CSV, verbose and plain. In both verbose and plain
--       records are separated by colons.  The difference between the two is that verbose
--       includes the credential state.  When ldap.savetype is used without ldap.saveprefix
--       then ldap-brute will be prefixed to all output filenames.
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- Version 0.6
-- Created 01/20/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/26/2010 - v0.2 - cleaned up unpwdb related code, fixed ssl stuff
-- Revised 02/17/2010 - v0.3 - added AD specific checks and fixed bugs related to LDAP base
-- Revised 08/07/2011 - v0.4 - adjusted AD match strings to be level independent, added additional account condition checks
-- Revised 09/04/2011 - v0.5 - added support for creds library, saving output to file
-- Revised 09/09/2011 - v0.6 - added support specifying a UPN suffix via ldap.upnsuffx, changed account status text for consistency.

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

	local result, response, status, err, context, output, valid_accounts = {}, nil, nil, nil, nil, nil, {}	
	local usernames, passwords, username, password, fq_username
	local user_cnt, invalid_account_cnt, tot_tries = 0, 0, 0
	
	local clock_start = nmap.clock_ms()
	
	local ldap_anonymous_bind = string.char( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 )
	local socket, _, opt = comm.tryssl( host, port, ldap_anonymous_bind, nil )
	
	local base_dn = stdnse.get_script_args('ldap.base')
	local upn_suffix = stdnse.get_script_args('ldap.upnsuffix')
		
	local output_type = stdnse.get_script_args('ldap.savetype')
	
	local output_prefix = nil
	if ( stdnse.get_script_args('ldap.saveprefix') ) then
		output_prefix = stdnse.get_script_args('ldap.saveprefix')
	elseif ( output_type ) then
		output_prefix = "ldap-brute"
	end
	
	local credTable = creds.Credentials:new(SCRIPT_NAME, host, port)
	
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
		elseif upn_suffix then
			fq_username = ("%s@%s"):format(username, upn_suffix)
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
			if not status and response:match("AcceptSecurityContext error, data 525,") then
				invalid_account_cnt = invalid_account_cnt + 1
				break
			end

			-- Account Locked Out
			if not status and response:match("AcceptSecurityContext error, data 775,") then
				table.insert( valid_accounts, string.format("%s => Valid credentials, account locked", fq_username ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s => Valid credentials, account locked", fq_username ))
				credTable:add(fq_username,password, creds.State.LOCKED_VALID)
				break
			end

			-- Login correct, account disabled
			if not status and response:match("AcceptSecurityContext error, data 533,") then
				table.insert( valid_accounts, string.format("%s:%s => Valid credentials, account disabled", fq_username, password:len()>0 and password or "<empty>" ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials, account disabled", fq_username, password:len()>0 and password or "<empty>" ))
				credTable:add(fq_username,password, creds.State.DISABLED_VALID)
				break
			end

			-- Login correct, user must change password
			if not status and response:match("AcceptSecurityContext error, data 773,") then
				table.insert( valid_accounts, string.format("%s:%s => Valid credentials, password must be changed at next logon", fq_username, password:len()>0 and password or "<empty>" ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials, password must be changed at next logon", fq_username, password:len()>0 and password or "<empty>" ))
				credTable:add(fq_username,password, creds.State.CHANGEPW)
				break
			end
			
			-- Login correct, user account expired
			if not status and response:match("AcceptSecurityContext error, data 701,") then
				table.insert( valid_accounts, string.format("%s:%s => Valid credentials, account expired", fq_username, password:len()>0 and password or "<empty>" ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials, account expired", fq_username, password:len()>0 and password or "<empty>" ))
				credTable:add(fq_username,password, creds.State.EXPIRED)
				break
			end
			
			-- Login correct, user account logon time restricted
			if not status and response:match("AcceptSecurityContext error, data 530,") then
				table.insert( valid_accounts, string.format("%s:%s => Valid credentials, account cannot log in at current time", fq_username, password:len()>0 and password or "<empty>" ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials, account cannot log in at current time", fq_username, password:len()>0 and password or "<empty>" ))
				credTable:add(fq_username,password, creds.State.TIME_RESTRICTED)
				break
			end
			
			-- Login correct, user account can only log in from certain workstations
			if not status and response:match("AcceptSecurityContext error, data 531,") then
				table.insert( valid_accounts, string.format("%s:%s => Valid credentials, account cannot log in from current host", fq_username, password:len()>0 and password or "<empty>" ) )
				stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials, account cannot log in from current host", fq_username, password:len()>0 and password or "<empty>" ))
				credTable:add(fq_username,password, creds.State.HOST_RESTRICTED)
				break
			end

			--Login, correct
			if status then
				status = is_valid_credential( socket, context )
				if status then
					table.insert( valid_accounts, string.format("%s:%s => Valid credentials", fq_username, password:len()>0 and password or "<empty>" ) )
					stdnse.print_verbose(2, string.format(" ldap-brute: %s:%s => Valid credentials", fq_username, password:len()>0 and password or "<empty>" ) )
					-- Add credentials for other ldap scripts to use
					if nmap.registry.ldapaccounts == nil then
						nmap.registry.ldapaccounts = {}
					end	
					nmap.registry.ldapaccounts[fq_username]=password
					credTable:add(fq_username,password, creds.State.VALID)
					
					break
				end
			end			
		end
		passwords("reset")
	end

	stdnse.print_debug( "Finished brute against LDAP, total tries: %d, tps: %d", tot_tries, ( tot_tries / ( ( nmap.clock_ms() - clock_start ) / 1000 ) ) )

	if ( invalid_account_cnt == user_cnt and base_dn ~= nil ) then
		return "WARNING: All usernames were invalid. Invalid LDAP base?"
	end
	
	
	
	if output_prefix then
		local output_file = output_prefix .. "_" .. host.ip .. "_" .. port.number
		status, err = credTable:saveToFile(output_file,output_type)
		if not status then
			stdnse.print_debug(err)
		end
	end

	if err then
		output = stdnse.format_output(true, valid_accounts ) .. stdnse.format_output(true, err) or stdnse.format_output(true, err)
	else
		output = stdnse.format_output(true, valid_accounts) or ""
	end
	
	return output

end
