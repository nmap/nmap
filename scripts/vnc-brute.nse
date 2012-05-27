local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vnc = require "vnc"

description = [[
Performs brute force password auditing against VNC servers.
]]

---
-- @usage
-- nmap --script vnc-brute -p 5900 <host>
--
-- @output
-- PORT     STATE  SERVICE REASON
-- 5900/tcp open   vnc     syn-ack
-- | vnc-brute:  
-- |   Accounts
-- |_    123456 => Valid credentials
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
--

--
-- Version 0.1
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(5901, "vnc", "tcp", "open")

Driver = 
{

	new = function(self, host, port)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		return o
	end,
	
	connect = function( self )
		local status, data 
		self.vnc = vnc.VNC:new( self.host.ip, self.port.number )
		status, data = self.vnc:connect()
		if ( not(status) ) then
			local err = brute.Error:new( "VNC connect failed" )
			-- This might be temporary, set the retry flag
			err:setRetry( true )
			return false, err
		end
		return true
	end,
	--- Attempts to login to the VNC server
	--
	-- @param username string containing the login username
	-- @param password string containing the login password
	-- @return status, true on success, false on failure
	-- @return brute.Error object on failure
	--         brute.Account object on success
	login = function( self, username, password )

		local status, data = self.vnc:handshake()
		if ( not(status) and ( data:match("Too many authentication failures") or
			data:match("Your connection has been rejected.") ) ) then
			local err = brute.Error:new( data )
			err:setAbort( true )
			return false, err			
		elseif ( not(status) ) then
			local err = brute.Error:new( "VNC handshake failed" )
			-- This might be temporary, set the retry flag
			err:setRetry( true )
			return false, err
		end

		status, data = self.vnc:login( nil, password )

		if ( status ) then
			return true, brute.Account:new("", password, creds.State.VALID)
		elseif ( not( data:match("Authentication failed") ) ) then
			local err = brute.Error:new( data )
			-- This might be temporary, set the retry flag
			err:setRetry( true )
			return false, err			
		end

		return false, brute.Error:new( "Incorrect password" )

	end,
	
	disconnect = function( self )
		self.vnc:disconnect()
	end,
	
	check = function( self )
		local vnc = vnc.VNC:new( self.host.ip, self.port.number )
		local status, data 

		status, data = vnc:connect()
		if ( not(status) ) then
			return stdnse.format_output( false, data )
		end

		status, data = vnc:handshake()
		if ( not(status) ) then
			return stdnse.format_output( false, data )
		end

		if ( vnc:supportsSecType(vnc.sectypes.NONE) ) then
			return false, "No authentication required"
		end

		status, data = vnc:login( nil, "is_sec_mec_supported?" )
		if ( data:match("The server does not support.*security type") ) then
			return stdnse.format_output( false, "  \n  " .. data )
		end
				
		return true
	end,
	
}


action = function(host, port)
	local status, result 
	local engine = brute.Engine:new(Driver, host, port )
	
	engine.options.script_name = SCRIPT_NAME
	engine.options.firstonly = true
	engine.options:setOption( "passonly", true )
	
	status, result = engine:start()

	return result
end
