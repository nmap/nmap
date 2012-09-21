local citrixxml = require "citrixxml"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Attempts to guess valid credentials for the Citrix PN Web Agent XML
Service. The XML service authenticates against the local Windows server
or the Active Directory.

This script makes no attempt of preventing account lockout. If the
password list contains more passwords than the lockout-threshold
accounts will be locked.
]]

---
-- @usage
-- nmap --script=citrix-brute-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>
--
-- @output
-- PORT     STATE SERVICE    REASON
-- 8080/tcp open  http-proxy syn-ack
-- | citrix-brute-xml:  
-- |   Joe:password => Must change password at next logon
-- |   Luke:summer => Login was successful
-- |_  Jane:secret => Account is disabled

-- Version 0.2

-- Created 11/30/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 12/02/2009 - v0.2 - Use stdnse.format_ouput for output


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.portnumber({8080,80,443}, "tcp")

--- Verifies if the credentials (username, password and domain) are valid
--
-- @param host string, the ip against which to perform
-- @param port number, the port number of the XML service
-- @param username string, the username to authenticate as
-- @param password string, the password to authenticate with
-- @param domain string, the Windows domain to authenticate against
--
-- @return success, message
--  
function verify_password( host, port, username, password, domain )

	local response = citrixxml.request_validate_credentials(host, port, {Credentials={Domain=domain, Password=password, UserName=username}})
	local cred_status = citrixxml.parse_validate_credentials_response(response)
	
	local account = {}

	account.username = username
	account.password = password
	account.domain = domain
			
	if cred_status.ErrorId then
		if cred_status.ErrorId == "must-change-credentials" then
			account.valid = true
			account.message = "Must change password at next logon"
		elseif cred_status.ErrorId == "account-disabled" then
			account.valid = true
			account.message = "Account is disabled"
		elseif cred_status.ErrorId == "account-locked-out" then
			account.valid = false
			account.message = "Account Locked Out"
		elseif cred_status.ErrorId == "failed-credentials" then
			account.valid = false
			account.message = "Incorrect Password"
		elseif cred_status.ErrorId == "unspecified" then
			account.valid = false
			account.message = "Unspecified"
		else
			print("UNKNOWN response: " .. response)
			account.valid = false
			account.message = "failed"
		end
	else
		account.message = "Login was successful"
		account.valid = true
	end

	return account
	
end

--- Formats the result from the table of valid accounts
--
-- @param accounts table containing accounts (tables)
-- @return string containing the result
function create_result_from_table(accounts)

	local result = ""

	for _, account in ipairs(accounts) do		
		result = result .. "  " .. account.username .. ":" .. account.password .. " => " .. account.message .. "\n"
	end
	
	return "\n" .. result
end

action = function(host, port)

	local status, nextUser, nextPass
	local username, password
	local args = nmap.registry.args
	local ntdomain = args.ntdomain
	local valid_accounts = {}
	
	if not ntdomain then
		return "FAILED: No domain specified (use ntdomain argument)"
	end
	
	status, nextUser = unpwdb.usernames()
	
	if not status then
		return
	end

	status, nextPass = unpwdb.passwords()

	if not status then
		return
	end
	
	username = nextUser()
	
	-- iterate over userlist
	while username do
		password = nextPass()
		
		-- iterate over passwordlist
		while password do
			local result = "Trying " .. username .. "/" .. password .. " "
			local account = verify_password(host.ip, port.number, username, password, ntdomain)
			
			if account.valid then
				
				table.insert(valid_accounts, account)
				
				if account.valid then
					stdnse.print_debug(1, "Trying %s/%s => Login Correct, Info: %s", username, password, account.message)
				else
					stdnse.print_debug(1, "Trying %s/%s => Login Correct", username, password)					
				end
			else
				stdnse.print_debug(1, "Trying %s/%s => Login Failed, Reason: %s", username, password, account.message)
			end
			password = nextPass()
		end
	
		nextPass("reset")
		username = nextUser()
	end
		
	return create_result_from_table(valid_accounts)
end
