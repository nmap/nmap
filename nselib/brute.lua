---
-- The brute library is an attempt to create a common framework for performing
-- password guessing against remote services. 
--
--
-- Summary
-- -------
-- The library currently attempts to parallellize the guessing by starting
-- a number of working threads. The number of threads can be defined using
-- the brute.threads argument, it defaults to 10.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--	 o Account
--		- Implmements a simple account class, that converts account "states"
--		  to common text representation.
--
--	 o Engine
--		- The actual engine doing the brute-forcing 
--
--	 o Error
--		- Class used to return errors back to the engine
--
--   o Options
--		- Stores any options that should be used during brute-forcing
--
-- In order to make use of the framework a script needs to implement a Driver 
-- class. The Driver class is then to be passed as a parameter to the Engine 
-- constructor, which creates a new instance for each guess. The Driver class 
-- SHOULD implement the following four methods:
--
-- - Driver:login = function( self, username, password )
-- - Driver:check = function( self )
-- - Driver:connect = function( self )
-- - Driver:disconnect = function( self )
--
-- The login method does not need a lot of explanation. The purpose of the
-- check method is to be able to determine whether the script has all the
-- information it needs, before starting the brute force. It's the method
-- where you should check eg. if the correct database or repository URL was
-- specified or not. On success, the check method returns true, on failure
-- it returns false and the brute force engine aborts.
--
-- The connect method provides the framework with the ability to ensure that
-- the thread can run once it has been dispatched a set of credentials. As
-- the sockets in NSE are limited we want to limit the risk of a thread 
-- blocking, due to insufficient free sockets, AFTER it has aquired a username
-- and password pair.
--
-- Example
-- -------
-- The following sample code illustrates how to implement a sample Driver that 
-- sends each username and password over a socket.
--
-- <code>
--   Driver = {
--		new = function(self, host, port, options)
--			local o = {}
--       	setmetatable(o, self)
--	        self.__index = self
--			o.host = host
--			o.port = port
--			o.options = options
--			return o
--		end,
--		connect = function( self )
--			self.socket = nmap.new_socket()
--			return self.socket:connect( self.host.ip, self.port.number, "tcp" )
--		end,
--		disconnect = function( self )
--			return self.socket:close()
--		end, 
--		check = function( self ) 
--			return true
--		end,
--		login = function( self, username, password )
--			local status, err, data
--			status, err = self.socket:send( username .. ":" .. password)
--			status, data = self.socket:receive_bytes(1)
--
--			if ( data:match("SUCCESS") ) then
--				return true, brute.Account:new(username, password, "OPEN")
--			end
--			return false, brute.Error:new( "login failed" )
--		end,
--   }
-- </code>
--
-- The following sample code illustrates how to pass the Driver off to the
-- brute engine.
--
-- <code>
--   action = function(host, port)
--      local options = { key1 = val1, key2 = val2 }
--      local status, accounts = brute.Engine:new(Driver, host, port, options):start()
--	    if( not(status) ) then
--	       return accounts
--      end
--      return stdnse.format_output( true, accounts )
--   end
-- </code>
--
-- For a complete example of a brute implementation consult the 
-- svn-brute.nse or vnc-brute.nse scripts
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
--
-- @args brute.emptypass guess an empty password for each user (default: true)
-- @args brute.useraspass guess the username as password for each user
--	     (default: true)
-- @args brute.unique make sure that each password is only guessed once
--	     (default: true)
-- @args brute.firstonly stop guessing after first password is found
--	     (default: false)
-- @args brute.passonly iterate over passwords only for services that provide
--       only a password for authentication. (default: false)
-- @args brute.retries the number of times to retry if recoverable failures
--		 occure. (default: 3)
-- @args brute.delay the number of seconds to wait between guesses (default: 0)
-- @args brute.threads the number of initial worker threads, the number of
--		 active threads will be automatically adjusted.
-- @args brute.mode can be user or pass and determines if passwords are guessed
--       against users (user) or users against passwords (pass). 
--       (default: pass)

--
-- Version 0.5
-- Created 06/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/13/2010 - v0.2 - added connect, disconnect methods to Driver
--							   <patrik@cqure.net>
-- Revised 07/21/2010 - v0.3 - documented missing argument brute.mode
-- Revised 07/23/2010 - v0.4 - fixed incorrect statistics and changed output to 
--							   include statistics, and to display "no accounts
--							   found" message.
-- Revised 08/14/2010 - v0.5 - added some documentation and smaller changes per
--                             David's request.

module(... or "brute", package.seeall)
require 'unpwdb'

-- Options that can be set through --script-args
Options = {

	mode = "password",
	
	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.empty_password = self.checkBoolArg("brute.emptypass", true)
		o.user_as_password = self.checkBoolArg("brute.useraspass", true)
		o.check_unique = self.checkBoolArg("brute.unique", true)
		o.firstonly = self.checkBoolArg("brute.firstonly", false)
		o.passonly = self.checkBoolArg("brute.passonly", false)
		o.max_retries = tonumber( nmap.registry.args["brute.retries"] ) or 3
		o.delay = tonumber( nmap.registry.args["brute.delay"] ) or 0

		return o
	end,
	
	--- Checks if a script argument is boolean true or false
	--
	-- @param arg string containing the name of the argument to check
	-- @param default boolean containing the default value
	-- @return boolean, true if argument evaluates to 1 or true, else false
	checkBoolArg = function( arg, default )
		local val = nmap.registry.args[arg]
		
		if ( not(val) ) then
			return default
		elseif ( val == "true" or val=="1" ) then
			return true
		else
			return false
		end
	end,
	
	--- Sets the brute mode to either iterate over users or passwords
	-- @see description for more information.
	--
	-- @param mode string containing either "user" or "password"
	-- @return status true on success else false
	-- @return err string containing the error message on failure
	setMode = function( self, mode )
		if ( mode == "password" or mode == "user" ) then
			self.mode = mode
		else
			stdnse.print_debug("ERROR: brute.options.setMode: mode %s not supported", mode)
			return false, "Unsupported mode"
		end
		return true
	end,

	--- Sets an option parameter
	--
	-- @param param string containing the parameter name
	-- @param value string containing the parameter value
	setOption = function( self, param, value )
		self[param] = value
	end,

}

-- The account object which is to be reported back from each driver
Account =
{
	new = function(self, username, password, state)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.username = username
		o.password = password
		o.state = state
		return o
	end,
	
	--- Converts an account object to a printable script
	--
	-- @return string representation of object
	toString = function( self )
		local creds
		
		if ( #self.username > 0 ) then
			creds = ("%s:%s"):format( self.username, #self.password > 0 and self.password or "<empty>" )
		else
			creds = ("%s"):format( self.password )
		end
		
		-- An account have the following states
		--
		-- OPEN - Login was successful
		-- LOCKED - The account was locked
		-- DISABLED - The account was disabled
		if ( self.state == "OPEN" ) then
			return ("%s => Login correct"):format( creds )
		elseif ( self.state == "LOCKED" ) then
			return ("%s => Account locked"):format( creds )
		elseif ( self.state == "DISABLED" ) then
			return ("%s => Account disabled"):format( creds )
		else
			return ("%s => Account has unknown state (%s)"):format( creds, self.state )
		end
	end,
			
}

-- The Error class, is currently only used to flag for retries
-- It also contains the error message, if one was returned from the driver.
Error =
{
	retry = false,
	
	new = function(self, msg)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.msg = msg
		o.done = false
		return o
	end,
	
	--- Is the error recoverable?
	isRetry = function( self )
		return self.retry
	end,
	
	--- Set the error as recoverable
	setRetry = function( self, r )
		self.retry = r
	end,
	
	--- Set the error as abort all threads
	setAbort = function( self, b )
		self.abort = b
	end,
	
	--- Was the error abortable
	isAbort = function( self )
		return self.abort
	end,
	
	--- Get the error message reported
	getMessage = function( self )
		return self.msg
	end,
	
	isThreadDone = function( self )
		return self.done
	end,
	
	setDone = function( self, b )
		self.done = b
	end,
	
}

-- The brute engine, doing all the nasty work
Engine =
{
	STAT_INTERVAL = 20,
	terminate_all = false,
	
	--- Creates a new Engine instance
	--
	-- @param driver, the driver class that should be instantiated
	-- @param host table as passed to the action method of the script
	-- @param port table as passed to the action method of the script
	-- @param options table containing any script specific options
	-- @return o new Engine instance	
	new = function(self, driver, host, port, options)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.driver = driver
		o.driver_options = options
		o.host = host
		o.port = port
		o.options = Options:new()
		o.found_accounts = {}
		o.threads = {}
		o.counter = 0
		o.max_threads = tonumber(nmap.registry.args["brute.threads"]) or 10
		o.error = nil
		o.tps = {}
		return o
	end,
	
	--- Limit the number of worker threads
	--
	-- @param max number containing the maximum number of allowed threads
	setMaxThreads = function( self, max )
		self.max_threads = max
	end,
			
	--- Returns the number of non-dead threads
	--
	-- @return count number of non-dead threads
	threadCount = function( self )
		local count = 0

		for thread in pairs(self.threads) do
			if ( coroutine.status(thread) == "dead" ) then
				self.threads[thread] = nil
			else
				count = count + 1
			end
		end
		return count
	end,
	
	--- Calculates the number of threads that are actually doing any work
	--
	-- @return count number of threads performing activity
	activeThreads = function( self )
		local count = 0

		for thread, v in pairs(self.threads) do
			if ( v.guesses ~= nil ) then
				count = count + 1
			end
		end
		return count		
	end,
	
	--- Does the actual authentication request
	--
	-- @return true on success, false on failure
	-- @return response Account on success, Error on failure
	doAuthenticate = function( self )

		local driver, status, response, creds
		local username, password
		local retries = self.options.max_retries
		local msg
		
		repeat
			driver = self.driver:new( self.host, self.port, self.driver_options )
			status = driver:connect()

			-- Did we succesfully connect?
			if ( status ) then

				if ( not(username) and not(password) ) then
					username, password = self.iterator()
				end

				-- make sure that all threads locked in connect stat terminate quickly
				if ( Engine.terminate_all ) then 
					driver:disconnect()
					return false
				end
		
				-- We've reached the end of the iterator, signal the thread to terminate
				if ( not(password) ) then
					driver:disconnect()
					self.threads[coroutine.running()].terminate = true
					return false
				end

				-- The username was already tested
				if ( self.found_accounts and self.found_accounts[username] ) then
					driver:disconnect()
					return false
				end
				
				-- Do we have a username or not?
				if ( username and #username > 0 ) then
					creds = ("%s/%s"):format(username, #password > 0 and password or "<empty>")
				else
					creds = ("%s"):format(#password > 0 and password or "<empty>")
				end

				-- Is this the first try?
				if ( retries ~= self.options.max_retries ) then
					msg = "Re-trying"
				else
					msg = "Trying"
				end
			
				stdnse.print_debug( "%s %s against %s:%d", msg, creds, self.host.ip, self.port.number )
				status, response = driver:login( username, password )

				driver:disconnect()
				driver = nil		
			end

			retries = retries - 1

		-- End if:
		-- * The guess was successfull
		-- * The response was not set to retry
		-- * We've reached the maximum retry attempts
		until( status or ( response and not( response:isRetry() ) ) or retries == 0)
			
		-- did we exhaust all retries, terminate and report?
		if ( retries == 0 ) then
			Engine.terminate_all = true
			self.error = "Too many retries, aborted ..."
		end
	
		return status, response
	end,
	
	login = function(self, valid_accounts )
		local username, password, creds
		local status, response, driver
		local interval_start, timediff = os.time(), nil
		local condvar = nmap.condvar( valid_accounts )		
		local thread_data = self.threads[coroutine.running()]
		
		while( true ) do
			
			-- Should we terminate all threads?
			if ( Engine.terminate_all or thread_data.terminate ) then
				break
			end
			
			status, response = self:doAuthenticate()
				
			if ( status ) then
				-- Prevent locked accounts from appearing several times
				if ( not(self.found_accounts) or self.found_accounts[response.username] == nil ) then
					if ( response.username and #response.username > 0 ) then
						stdnse.print_debug("Found valid password %s:%s on target %s", response.username, response.password, self.host.ip )
					else
						stdnse.print_debug("Found valid password %s on target %s", response.password, self.host.ip )
					end
					table.insert( valid_accounts, response:toString() )
					self.found_accounts[response.username] = true
					-- Check if firstonly option was set, if so abort all threads
					if ( self.options.firstonly ) then
						Engine.terminate_all = true
					end
				end
			else
				if ( response and response:isAbort() ) then
					Engine.terminate_all = true
					self.error = response:getMessage()
					break
				elseif( response and response:isThreadDone() ) then
					break
				end
			end
				
			-- Increase the amount of total guesses
			self.counter = self.counter + 1
			timediff = (os.time() - interval_start)
	
			-- This thread made another guess
			thread_data.guesses = ( thread_data.guesses and thread_data.guesses + 1 or 1 )

			-- Dump statistics at regular intervals
			if ( timediff > Engine.STAT_INTERVAL ) then
				interval_start = os.time()
				local tps = self.counter / ( os.time() - self.starttime )
				table.insert(self.tps, tps )
				stdnse.print_debug("threads=%d,tps=%d", self:activeThreads(), tps )
			end

			-- if delay was speciefied, do sleep
			if ( self.options.delay > 0 ) then
				stdnse.sleep( self.options.delay )
			end

		end
		condvar("broadcast")
	end,
			
	--- Starts the brute-force
	--
	-- @return status true on success, false on failure
	-- @return err string containing error message on failure
	start = function(self)
		local status, usernames, passwords, response
		local result, valid_accounts, stats = {}, {}, {}
		local condvar = nmap.condvar( valid_accounts )
		local sum, tps, time_diff = 0, 0, 0
		
		-- check if the driver is ready!
		status, response = self.driver:new( self.host, self.port ):check()
		if( not(status) ) then
			return false, response
		end
		
		status, usernames = unpwdb.usernames()
		if ( not(status) ) then
			return false, "Failed to load usernames"
		end

		-- make sure we have a valid pw file
		status, passwords = unpwdb.passwords()
		if ( not(status) ) then
			return false, "Failed to load passwords"
		end
	
		-- Are we guessing against a service that has no username (eg. VNC)
		if ( self.options.passonly ) then
			local function single_user_iter(next)
				local function next_user()
					coroutine.yield( "" )
				end
				return coroutine.wrap(next_user)
			end
			self.iterator = Engine.usrpwd_iterator( self, single_user_iter(), passwords )
		elseif ( nmap.registry.args['brute.mode'] and nmap.registry.args['brute.mode'] == 'user' ) then
			self.iterator = Engine.usrpwd_iterator( self, usernames, passwords )
		elseif( nmap.registry.args['brute.mode'] and nmap.registry.args['brute.mode'] == 'pass' ) then
			self.iterator = Engine.pwdusr_iterator( self, usernames, passwords )
		elseif ( nmap.registry.args['brute.mode'] ) then
			return false, ("Unsupported mode: %s"):format(nmap.registry.args['brute.mode'])
		else
			self.iterator = Engine.pwdusr_iterator( self, usernames, passwords )
		end

		self.starttime = os.time()

		-- Startup all worker threads
		for i=1, self.max_threads do
			local co = stdnse.new_thread( self.login, self, valid_accounts )
			self.threads[co] = {}
			self.threads[co].running = true
		end

		-- wait for all threads to finnish running
		while self:threadCount()>0 do
			condvar("wait")
	 	end
		
		-- Did we find any accounts, if so, do formatting
		if ( #valid_accounts > 0 ) then
			valid_accounts.name = "Accounts"
			table.insert( result, valid_accounts )
		else
			table.insert( result, {"No valid accounts found", name="Accounts"} )
		end
		
		-- calculate the average tps
		for _, v in ipairs( self.tps ) do
			sum = sum + v
		end
		time_diff = ( os.time() - self.starttime )
		if ( time_diff == 0 ) then time_diff = 1 end
		if ( sum == 0 ) then 
			tps = self.counter / time_diff 
		else
			tps = sum / #self.tps
		end

		-- Add the statistics to the result
		table.insert(stats, ("Perfomed %d guesses in %d seconds, average tps: %d"):format( self.counter, time_diff, tps ) )
		stats.name = "Statistics"
		table.insert( result, stats )

		if ( #result ) then
			result = stdnse.format_output( true, result )
		else
			result = ""
		end
		
		-- Did any error occure? If so add this to the result.
		if ( self.error ) then
			result = result .. ("  \n\n  ERROR: %s"):format( self.error )
			return false, result
		end
				
		return true, result
	end,
	
	--- Credential iterator, tries every user for each password
	--
	-- @param usernames iterator from unpwdb
	-- @param passwords iterator from unpwdb
	-- @return username string
	-- @return password string
	pwdusr_iterator = function(self, usernames, passwords)
		local function next_password_username ()
			local tested_creds = {}

			-- should we check for empty passwords?
			if ( self.options.empty_password ) then
				for username in usernames do
					if ( not(tested_creds[username]) ) then
						tested_creds[username] = {}
					end
					tested_creds[username][""] = true
					if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
						coroutine.yield(username, "")
					end
				end
			end
			usernames("reset")
			
			-- should we check for same password as username
			if ( self.options.user_as_password ) then
				for username in usernames do
					if ( not( tested_creds[username] ) ) then
						tested_creds[username] = {}
					end
					
					tested_creds[username][username] = true
					if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
						coroutine.yield(username, username)
					end
				end
			end
			usernames("reset")

			for password in passwords do								
				for username in usernames do
					if ( not(tested_creds[username]) ) then
						tested_creds[username] = {}
					end
					if ( self.options.check_unique and not(tested_creds[username][password]) ) then
						tested_creds[username][password] = true
						if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
							coroutine.yield(username, password)
						end
					end
				end
				usernames("reset")
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap(next_password_username)
	end,
		
	--- Credential iterator, tries every password for each user
	--
	-- @param usernames iterator from unpwdb
	-- @param passwords iterator from unpwdb
	-- @return username string
	-- @return password string
	usrpwd_iterator = function(self, usernames, passwords)
		local function next_username_password ()
			local tested_creds = {}

			for username in usernames do
				-- set's up a table to track tested credentials
				tested_creds[username] = {}
				
				-- should we check for empty passwords?
				if ( self.options.empty_password ) then
					tested_creds[username][""] = true
					if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
						coroutine.yield(username, "")
					end
				end
				
				-- should we check for same password as username
				if ( self.options.user_as_password and not(self.options.passonly) ) then
					tested_creds[username][username:lower()] = true
					if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
						coroutine.yield(username, username:lower())
					end
				end
				
				for password in passwords do
					if ( self.options.check_unique and not(tested_creds[username][password]) ) then
						tested_creds[username][password] = true
						if ( not(self.found_accounts) or not(self.found_accounts[username]) ) then
							coroutine.yield(username, password)
						end
					end
				end
				passwords("reset")
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap(next_username_password)
	end,

}

