local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Performs brute force password auditing against the Lotus Domino Console.
]]

---
-- @usage
-- nmap --script domcon-brute -p 2050 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 2050/tcp open  unknown syn-ack
-- | domcon-brute:  
-- |   Accounts
-- |_    patrik karlsson:secret => Login correct
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
--
-- Version 0.1
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(2050, "", "tcp", "open")

local not_admins = {}

SocketPool = {
	
	new = function(self, max_sockets)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.max_sockets = max_sockets
		o.pool = {}
		return o
	end,
	
	getSocket = function(self, host, port)
		while(true) do
			for i=1, #self.pool do
				if ( not( self.pool[i].inuse ) ) then
					self.pool[i].inuse = true
					return self.pool[i].socket
				end
			end
			if ( #self.pool < self.max_sockets ) then
				local socket = nmap.new_socket()
				local status = socket:connect( host.ip, port.number, "tcp")
				
				if ( status ) then
					socket:reconnect_ssl()
				end
			
				if ( status and socket ) then
					table.insert( self.pool, {['socket'] = socket, ['inuse'] = false})
				end
			end
			stdnse.sleep(1)
		end
	end,
	
	releaseSocket = function( self, socket )
		for i=1, #self.pool do
			if( socket == self.pool[i].socket ) then
				self.pool[i].inuse = false
				break
			end
		end
	end,
		
	shutdown = function( self )
		for i=1, #self.pool do
			self.pool[i].socket:close()
		end
	end,
	
}

Driver = 
{

	new = function(self, host, port, options)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.sockpool = options
		return o
	end,
	
	connect = function( self )
		self.socket = self.sockpool:getSocket( self.host, self.port )
	
		if ( self.socket ) then
			return true
		else
			return false
		end
	end,

	--- Attempts to login to the Lotus Domino Console
	--
	-- @param username string containing the login username
	-- @param password string containing the login password
	-- @return status, true on success, false on failure
	-- @return brute.Error object on failure
	--         brute.Account object on success
	login = function( self, username, password )
		local data = ("#UI %s,%s\n"):format(username,password)
		local status
		
		if ( not_admins[username] ) then
			return false, brute.Error:new( "Incorrect password" )
		end

		status, data = self.socket:send( data )
		if ( not(status) ) then
			local err = brute.Error:new( data )
			err:setRetry(true)
			return false, err
		end
		
		status, data = self.socket:receive_bytes(5)

		if ( status and data:match("NOT_REG_ADMIN") ) then
			not_admins[username] = true
		elseif( status and data:match("VALID_USER") ) then
			return true, brute.Account:new( username, password, creds.State.VALID)
		end

		return false, brute.Error:new( "Incorrect password" )

	end,
	
	disconnect = function( self )
		self.sockpool:releaseSocket( self.socket )
	end,
		
}


action = function(host, port)
	local status, result 
	local pool = SocketPool:new(10)
	local engine = brute.Engine:new(Driver, host, port, pool )
   	
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()
	pool:shutdown()
	
	return result
end
