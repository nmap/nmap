description = [[
Performs brute force password auditing against Oracle servers.
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
-- |     haxxor:haxxor => Login correct
-- |   Statistics
-- |_    Perfomed 157 guesses in 8 seconds, average tps: 19
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
-- @args oracle-brute.sid the instance against which to perform password
--       guessing
--

--
-- Version 0.2
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/23/2010 - v0.2 - added script usage and output and 
-- 							 - oracle-brute.sid argument

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'brute'
if pcall(require,"openssl") then
  require("tns")
else
  portrule = function() return false end
  action = function() end
  stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.",
      SCRIPT_NAME)
  return;
end

portrule = shortport.port_or_service(1521, "oracle-tns", "tcp", "open")

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
	
	--- Connects performs protocol negotiation
	--
	-- @return true on success, false on failure
	connect = function( self )
		local status, data
		self.helper = tns.Helper:new( self.host, self.port, nmap.registry.args['oracle-brute.sid'] )
		
		local MAX_RETRIES = 10
		local tries = MAX_RETRIES
		
		-- This loop is intended for handling failed connections
		-- A connection may fail for a number of different reasons.
		-- For the moment, we're just handling the error code 12520
		--
		-- Error 12520 has been observed on Oracle XE and seems to
		-- occur when a maximum connection count is reached.
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
		until( tries == 0 or data ~= "12520")
		
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
		
		if ( status ) then
			return true, brute.Account:new(username, password, "OPEN")
		-- Check for account locked message
		elseif ( data:match("ORA[-]28000") ) then
			return true, brute.Account:new(username, password, "LOCKED")
		-- check for any other message
		elseif ( data:match("ORA[-]%d+")) then
			stdnse.print_debug(3, "username: %s, password: %s, error: %s", username, password, data )
			return false, brute.Error:new(data)
		-- any other errors are likely communication related, attempt to re-try
		else
			local err = brute.Error:new(data)
			err:setRetry(true)
			return false, err
		end

		return false, brute.Error:new( data )

	end,
	
	--- Disconnects and terminates the Oracle TNS communication
	disconnect = function( self )
		self.helper:Close()
	end,
	
	--- Perform a connection with the helper, this makes sure that the Oracle
	-- instance is correct.
	--
	-- @return status true on success false on failure
	-- @return err containing the error message on failure
	check = function( self )
		local helper = tns.Helper:new( self.host, self.port, nmap.registry.args['oracle-brute.sid'] )
		local status, err = helper:Connect()

		if( status ) then
			helper:Close()
			return true
		end

		return false, err
	end,
	
}


action = function(host, port)
	local status, result 
	local engine = brute.Engine:new(Driver, host, port )
	
	if ( not( nmap.registry.args['oracle-brute.sid'] ) and not( nmap.registry.args['tns.sid'] ) ) then
		return "ERROR: Oracle instance not set (see oracle-brute.sid or tns.sid)"
	end
	
	status, result = engine:start()

	return result
end
