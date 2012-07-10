local brute = require "brute"
local coroutine = require "coroutine"
local creds = require "creds"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tns = require "tns"

local openssl = stdnse.silent_require "openssl"

description = [[
Performs brute force password auditing against Oracle servers.

Running it in default mode it performs an audit against a list of common
Oracle usernames and passwords. The mode can be changed by supplying the
argument oracle-brute.nodefault at which point the script will use the
username- and password- lists supplied with Nmap. Custom username- and
password- lists may be supplied using the userdb and passdb arguments.
The default credential list can be changed too by using the brute.credfile
argument. In case the userdb or passdb arguments are supplied, the script
assumes that it should run in the nodefault mode.

In modern versions of Oracle password guessing speeds decrease after a few
guesses and remain slow, due to connection throttling.

WARNING: The script makes no attempt to discover the amount of guesses
that can be made before locking an account. Running this script may therefor
result in a large number of accounts being locked out on the database server.
]]

---
-- @usage
-- nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL <host>
--
-- @output
-- PORT     STATE  SERVICE REASON
-- 1521/tcp open  oracle  syn-ack
-- | oracle-brute:  
-- |   Accounts
-- |     system:powell => Account locked
-- |     haxxor:haxxor => Valid credentials
-- |   Statistics
-- |_    Perfomed 157 guesses in 8 seconds, average tps: 19
--
-- @args oracle-brute.sid - the instance against which to perform password
--                          guessing
-- @args oracle-brute.nodefault - do not attempt to guess any Oracle default
--                                accounts

--
-- Version 0.3
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/23/2010 - v0.2 - added script usage and output and 
-- 							 - oracle-brute.sid argument
-- Revised 07/25/2011 - v0.3 - added support for guessing default accounts
--                             changed code to use ConnectionPool
-- Revised 03/13/2012 - v0.4 - revised by László Tóth
--                             added support for SYSDBA accounts
-- Revised 08/07/2012 - v0.5 - revised to suit the changes in brute
-- 							   library [Aleksandar Nikolic]

--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(1521, "oracle-tns", "tcp", "open")

local ConnectionPool = {}
local sysdba = {}

Driver = 
{

	new = function(self, host, port, sid )
		local o = { host = host, port = port, sid = sid }
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	--- Connects performs protocol negotiation
	--
	-- @return true on success, false on failure
	connect = function( self )		
		local MAX_RETRIES = 10
		local tries = MAX_RETRIES
		
		self.helper = ConnectionPool[coroutine.running()]
		if ( self.helper ) then return true end
		
		self.helper = tns.Helper:new( self.host, self.port, self.sid )
		
		-- This loop is intended for handling failed connections
		-- A connection may fail for a number of different reasons.
		-- For the moment, we're just handling the error code 12520
		--
		-- Error 12520 has been observed on Oracle XE and seems to
		-- occur when a maximum connection count is reached.
		local status, data
		repeat
			if ( tries < MAX_RETRIES ) then
				stdnse.print_debug(2, "%s: Attempting to re-connect (attempt %d of %d)", SCRIPT_NAME, MAX_RETRIES - tries, MAX_RETRIES)
			end
			status, data = self.helper:Connect()
			if ( not(status) ) then
				stdnse.print_debug(2, "%s: ERROR: An Oracle %s error occured", SCRIPT_NAME, data)
				self.helper:Close()
			else
				break
			end
			tries = tries - 1
			stdnse.sleep(1)
		until( tries == 0 or data ~= "12520" )
		
		if ( status ) then
			ConnectionPool[coroutine.running()] = self.helper
		end
		
		return status, data
	end,
	
	--- Attempts to login to the Oracle server
	--
	-- @param username string containing the login username
	-- @param password string containing the login password
	-- @return status, true on success, false on failure
	-- @return brute.Error object on failure
	--         brute.Account object on success
	login = function( self, username, password )
		local status, data = self.helper:Login( username, password )
		
		if ( sysdba[username] ) then
			return false, brute.Error:new("Account already discovered")
		end
		
		if ( status ) then
			self.helper:Close()
			ConnectionPool[coroutine.running()] = nil
			return true, brute.Account:new(username, password, creds.State.VALID)
		-- Check for account locked message
		elseif ( data:match("ORA[-]28000") ) then
			return true, brute.Account:new(username, password, creds.State.LOCKED)
		-- Check for account is SYSDBA message
		elseif ( data:match("ORA[-]28009") ) then
			sysdba[username] = true
			return true, brute.Account:new(username .. " as sysdba", password, creds.State.VALID)
		-- check for any other message
		elseif ( data:match("ORA[-]%d+")) then
			stdnse.print_debug(3, "username: %s, password: %s, error: %s", username, password, data )
			return false, brute.Error:new(data)
		-- any other errors are likely communication related, attempt to re-try
		else
			self.helper:Close()
			ConnectionPool[coroutine.running()] = nil
			local err = brute.Error:new(data)
			err:setRetry(true)
			return false, err
		end

		return false, brute.Error:new( data )

	end,
	
	--- Disconnects and terminates the Oracle TNS communication
	disconnect = function( self )
		return true
	end,
		
}


action = function(host, port)
	local DEFAULT_ACCOUNTS = "nselib/data/oracle-default-accounts.lst"
	local sid = stdnse.get_script_args('oracle-brute.sid') or
				stdnse.get_script_args('tns.sid')
	local engine = brute.Engine:new(Driver, host, port, sid)
	local mode = "default"
	
	if ( not(sid) ) then
		return "\n  ERROR: Oracle instance not set (see oracle-brute.sid or tns.sid)"
	end

	local helper = tns.Helper:new( host, port, sid )
	local status, result = helper:Connect()
	if ( not(status) ) then
		return "\n  ERROR: Failed to connect to oracle server"
	end
	helper:Close()

	local f

	if ( stdnse.get_script_args('userdb') or
		 stdnse.get_script_args('passdb') or
		 stdnse.get_script_args('oracle-brute.nodefault') or
		 stdnse.get_script_args('brute.credfile') ) then
		mode = nil
	end

	if ( mode == "default" ) then
		f = nmap.fetchfile(DEFAULT_ACCOUNTS)
		if ( not(f) ) then
			return ("\n  ERROR: Failed to find %s"):format(DEFAULT_ACCOUNTS)
		end

		f = io.open(f)
		if ( not(f) ) then
			return ("\n  ERROR: Failed to open %s"):format(DEFAULT_ACCOUNTS)
		end

		engine.iterator = brute.Iterators.credential_iterator(f)
	end
	
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()
	
	return result
end
