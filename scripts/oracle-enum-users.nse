description = [[
Attempts to enumerate valid Oracle user names against unpatched Oracle 11g
servers (this bug was fixed in Oracle's October 2009 Critical Patch Update).
]]

---
-- @usage
-- nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 <host>
--
-- If no userdb is supplied the default userlist is used
--
-- @output
-- PORT     STATE SERVICE REASON
-- 1521/tcp open  oracle  syn-ack
-- | oracle-enum-users:  
-- |   haxxor is a valid user account
-- |   noob is a valid user account
-- |_  patrik is a valid user account
--
-- The get_random_string function was stolen from Ron's smb code
--
-- @args oracle-enum-users.sid the instance against which to attempt user
--       enumeration

-- Version 0.3

-- Created 12/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 21/07/2010 - v0.2 - revised to work with patched systems <patrik>
-- Revised 21/07/2010 - v0.3 - removed references to smb in get_random_string

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'unpwdb'
if pcall(require,"openssl") then
  require("tns")
else
  portrule = function() return false end
  action = function() end
  stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.",
      SCRIPT_NAME)
  return;
end

portrule = shortport.port_or_service(1521, 'oracle-tns' )

local function checkAccount( host, port, user )
	
	local helper = tns.Helper:new( host, port, nmap.registry.args['oracle-enum-users.sid'] )
	local status, data = helper:Connect()
	local tnscomm, auth
	local auth_options = tns.AuthOptions:new()
	
	
	if ( not(status) ) then
		return false, data
	end

	-- A bit ugly, the helper should probably provide a getSocket function
	tnscomm = tns.Comm:new( helper.tnssocket )
	
	status, auth = tnscomm:exchTNSPacket( tns.Packet.PreAuth:new( user, auth_options ) )
	if ( not(status) ) then
		return false, auth
	end
	helper:Close()
	
	return true, auth["AUTH_VFR_DATA"]	
end

---Generates a random string of the requested length. This can be used to check how hosts react to 
-- weird username/password combinations. 
--@param length (optional) The length of the string to return. Default: 8. 
--@param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore. 
--@return The random string. 
local function get_random_string(length, set)
	if(length == nil) then
		length = 8
	end

	if(set == nil) then
		set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
	end

	local str = ""

	-- Seed the random number, if we haven't already
	if (not(nmap.registry.oracle_enum_users) or not(nmap.registry.oracle_enum_users.seeded)) then
		math.randomseed(os.time())
		nmap.registry.oracle_enum_users = {}
		nmap.registry.oracle_enum_users.seeded = true
	end

	for i = 1, length, 1 do
		local random = math.random(#set)
		str = str .. string.sub(set, random, random)
	end

	return str
end



action = function( host, port )

	local known_good_accounts = { "system", "sys", "dbsnmp", "scott" }

	local status, salt
	local count = 0
	local result = {}
	local usernames
	
	if ( not( nmap.registry.args['oracle-enum-users.sid'] ) and not( nmap.registry.args['tns.sid'] ) ) then
		return "ERROR: Oracle instance not set (see oracle-brute.sid or tns.sid)"
	end
	
	status, usernames = unpwdb.usernames()
	if( not(status) ) then
		return stdnse.format_output(true, "ERROR: Failed to load the usernames dictionary")
	end
	
	-- Check for some known good accounts
	for _, user in ipairs( known_good_accounts ) do
		status, salt = checkAccount(host, port, user)
		if( not(status) ) then return salt	end
		if ( salt ) then
			count = count + #salt
		end
	end
	
	-- did we atleast get a single salt back?
	if ( count < 20 ) then
		return stdnse.format_output(true, "ERROR: None of the known accounts were detected (oracle < 11g)")
	end
	
	-- Check for some known bad accounts
	count = 0
	for i=1, 10 do
		local user = get_random_string(10)
		status, salt = checkAccount(host, port, user)
		if( not(status) ) then return salt	end
		if ( salt ) then
			count = count + #salt
		end
	end

	-- It's unlikely that we hit 3 random combinations as valid users
	if ( count > 60 ) then
		return stdnse.format_output(true, ("ERROR: %d of %d random accounts were detected (Patched Oracle 11G or Oracle 11G R2)"):format(count/20, 10))
	end
	
	for user in usernames do
		status, salt = checkAccount(host, port, user)
		if ( not(status) ) then return salt end
		if ( salt and #salt == 20 ) then
			table.insert( result, ("%s is a valid user account"):format(user))
		end
	end
	
	if ( #result == 0 ) then
		table.insert( result, "Failed to find any valid user accounts")
	end
	
	return stdnse.format_output(true, result)
end
