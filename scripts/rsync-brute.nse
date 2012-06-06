local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"

local rsync = stdnse.silent_require "rsync"

description = [[
Performs brute force password auditing against the rsync remote file syncing protocol.
]]

---
-- @usage
-- nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' <ip>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 873/tcp open  rsync   syn-ack
-- | rsync-brute: 
-- |   Accounts
-- |     user1:laptop - Valid credentials
-- |     user2:password - Valid credentials
-- |   Statistics
-- |_    Performed 1954 guesses in 20 seconds, average tps: 97
--
-- @args rsync-brute.module - the module against which brute forcing should be performed



author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(873, "rsync", "tcp")

Driver = {
	
	new = function(self, host, port, options)
		local o = {	host = host, port = port, options = options	}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self)
		self.helper = rsync.Helper:new(self.host, self.port, self.options)
		return self.helper:connect()
	end,
	
	login = function(self, username, password)

		local status, data = self.helper:login(username, password)
		-- retry unless we have an authentication failed error
		if( not(status) and data ~= "Authentication failed" ) then
			local err = brute.Error:new( data )
			err:setRetry( true )
			return false, err
		elseif ( not(status) ) then
			return false, brute.Error:new( "Login failed" )
		else
			return true, brute.Account:new(username, password, creds.State.VALID)
		end
	end,
	
	disconnect = function( self )
		return self.helper:disconnect()
	end		
		
}

local function isModuleValid(host, port, module)
	local helper = rsync.Helper:new(host, port, { module = module })
	if ( not(helper) ) then
		return false, "Failed to create helper"
	end
	local status, data = helper:connect()
	if ( not(status) ) then
		return false, "Failed to connect to server"
	end
	status, data = helper:login()
	if ( status and data == "No authentication was required" ) then
		return false, data
	elseif ( not(status) and data == "Authentication required" ) then
		return true
	elseif ( not(status) and data == ("Unknown module '%s'"):format(module) ) then
		return false, data
	end
	return false, ("Brute pre-check failed for unknown reason: (%s)"):format(data)
end

action = function(host, port)
	
	local mod = stdnse.get_script_args(SCRIPT_NAME .. ".module")
	if ( not(mod) ) then
		return "\n  ERROR: rsync-brute.module was not supplied"
	end
	
	local status, err = isModuleValid(host, port, mod)
	if ( not(status) ) then
		return ("\n  ERROR: %s"):format(err)
	end
	
	local engine = brute.Engine:new(Driver, host, port, { module = mod })
	engine.options.script_name = SCRIPT_NAME
	local result
	status, result = engine:start()
	return result
end
