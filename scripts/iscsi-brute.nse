local brute = require "brute"
local creds = require "creds"
local iscsi = require "iscsi"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against iSCSI targets.
]]

---
-- @output
-- PORT     STATE SERVICE
-- 3260/tcp open  iscsi   syn-ack
-- | iscsi-brute: 
-- |   Accounts
-- |     user:password123456 => Valid credentials
-- |   Statistics
-- |_    Perfomed 5000 guesses in 7 seconds, average tps: 714

-- Version 0.1
-- Created 2010/11/18 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2010/11/27 - v0.2 - detect if no password is needed <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.portnumber(3260, "tcp", {"open", "open|filtered"})

Driver = {
	
	new = function(self, host, port)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.target = stdnse.get_script_args('iscsi-brute.target')
		return o
	end,
	
	connect = function( self )
		self.helper = iscsi.Helper:new( self.host, self.port )
		return self.helper:connect()
	end,
	
	login = function( self, username, password )
		local status = self.helper:login( self.target, username, password, "CHAP")
		
		if ( status ) then
			return true, brute.Account:new(username, password, creds.State.VALID)
		end
		
		return false, brute.Error:new( "Incorrect password" )
	end,
	
	disconnect = function( self )
		self.helper:close()
	end,
}


action = function( host, port )

	local target = stdnse.get_script_args('iscsi-brute.target')
	if ( not(target) ) then
		return "ERROR: No target specified (see iscsi-brute.target)"
	end
	
	local helper = iscsi.Helper:new( host, port )
	local status, err = helper:connect()
	if ( not(status) ) then return false, "Failed to connect" end

	local response
	status, response = helper:login( target )
	helper:logout()
	helper:close()

	if ( status ) then return "No authentication required" end

	local accounts

	local engine = brute.Engine:new(Driver, host, port)
	engine.options.script_name = SCRIPT_NAME
	status, accounts = engine:start()

	if ( status ) then return accounts end
end
