description = [[
Attempts to brute-force SIP accounts
]]

---
-- @usage
-- nmap -sU -p 5060 <target> --script=sip-brute
--
-- PORT     STATE         SERVICE
-- 5060/udp open|filtered sip
-- | sip-brute: 
-- |   Accounts
-- |     1000:password123 => Login correct
-- |   Statistics
-- |_    Performed 5010 guesses in 3 seconds, average tps: 1670

-- Version 0.1
-- Created 04/03/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require "shortport"
require "sip"
require "brute"

portrule = shortport.port_or_service(5060, "sip", "udp")

Driver = {
	
	new = function(self, host, port)
		local o = {}
   		setmetatable(o, self)
    	self.__index = self
		o.host = host
		o.port = port
		return o
	end,
	
	connect = function( self )
		self.helper = sip.Helper:new(self.host, self.port, { expires = 0 })
		local status, err = self.helper:connect()
		if ( not(status) ) then
			return "ERROR: Failed to connect to SIP server"
		end
		return true
	end,

	login = function( self, username, password )
		self.helper:setCredentials(username, password)
		status, err = self.helper:register()
		if ( not(status) ) then
			-- The 3CX System has an anti-hacking option that triggers after
			-- a certain amount of guesses. This protection basically prevents
			-- any connection from the offending IP at an application level.
			if ( err:match("^403 Forbidden") ) then
				local err = brute.Error:new("The systems seems to have blocked our IP")
				err:setAbort( true )
				return false, err
			end
			return false, brute.Error:new( "Incorrect password" )
		end
		return true, brute.Account:new(username, password, "OPEN")
	end,
	
	disconnect = function(self)	return self.helper:close() end,	
}

-- Function used to check if we can distinguish existing from non-existing
-- accounts. In order to do so we send a semi-random username and password
-- and interpret the response. Some servers will respond as if the login
-- was successful which makes it impossible to tell successfull logins
-- from non-existing accounts apart.
local function checkBadUser(host, port)
	math.randomseed( os.time() )
	local user = "baduser-" .. math.random(10000)
	local pass = "badpass-" .. math.random(10000)
	local helper = sip.Helper:new(host, port, { expires = 0 })
		
	print(user, pass)
	local status, err = helper:connect()
	if ( not(status) ) then return false, "ERROR: Failed to connect" end
	
	helper:setCredentials(user, pass)
	local status, err = helper:register()
	helper:close()
	return status, err
end

action = function(host, port)
	local force = stdnse.get_script_args("sip-brute.force")

	if ( not(force) ) then
		local status = checkBadUser(host, port)
		if ( status ) then
			return "\nERROR: Cannot detect non-existing user accounts, this will result in:\n" ..
				"  * Non-exisiting accounts being detected as found\n" ..
				"  * Passwords for existing accounts being correctly detected\n\n" ..
				"Supply the sip-brute.force argument to override"
		end
	end
	local engine = brute.Engine:new(Driver, host, port)
	local status, result = engine:start()
	return result
end