---
-- The brute library is an attempt to create a common framework for performing
-- password guessing against remote services. 
--
-- The library currently attempts to parallellize the guessing by starting
-- a number of working threads. The number of threads can be defined using
-- the brute.threads argument, it defaults to 10.
--
-- The library contains the following classes:
-- * <code>Account</code>
-- ** Implements a simple account class, that converts account "states" to common text representation.
-- ** The state can be either of the following: OPEN, LOCKED or DISABLED
-- * <code>Engine</code>
-- ** The actual engine doing the brute-forcing .
-- * <code>Error</code>
-- ** Class used to return errors back to the engine.
-- * <code>Options</code>
-- ** Stores any options that should be used during brute-forcing.
--
-- In order to make use of the framework a script needs to implement a Driver 
-- class. The Driver class is then to be passed as a parameter to the Engine 
-- constructor, which creates a new instance for each guess. The Driver class 
-- SHOULD implement the following four methods:
--
-- <code>
-- Driver:login = function( self, username, password )
-- Driver:check = function( self )
-- Driver:connect = function( self )
-- Driver:disconnect = function( self )
-- </code>
--
-- The <code>login</code> method does not need a lot of explanation. The login
-- function should return two parameters. If the login was successful it should
-- return true and an <code>Account</code>. If the login was a failure it
-- should return false and an <code>Error</code>. The driver can signal the
-- Engine to retry a set of credentials by calling the Error objects
-- <code>setRetry</code> method. It may also signal the Engine to abort all
-- password guessing by calling the Error objects <code>setAbort</code> method.
--
-- The following example code demonstrates how the Error object can be used.
-- 
-- <code>
-- 		-- After a number of incorrect attempts VNC blocks us, so we abort
-- 		if ( not(status) and x:match("Too many authentication failures") ) then
-- 			local err = brute.Error:new( data )
--			-- signal the engine to abort
-- 			err:setAbort( true )
-- 			return false, err			
-- 		elseif ( not(status) ) then
-- 			local err = brute.Error:new( "VNC handshake failed" )
-- 			-- This might be temporary, signal the engine to retry
-- 			err:setRetry( true )
-- 			return false, err
-- 		end
-- 		.
-- 		.
-- 		.
-- 		-- Return a simple error, no retry needed
-- 		return false, brute.Error:new( "Incorrect password" ) 
-- </code>
--
-- The purpose of the <code>check</code> method is to be able to determine
-- whether the script has all the information it needs, before starting the
-- brute force. It's the method where you should check, e.g., if the correct
-- database or repository URL was specified or not. On success, the
-- <code>check</code> method returns true, on failure it returns false and the
-- brute force engine aborts. 
--
-- NOTE: The <code>check</code> method is deprecated and will be removed from
-- all scripts in the future. Scripts should do this check in the action
-- function instead. 
--
-- The <code>connect</code> method provides the framework with the ability to
-- ensure that the thread can run once it has been dispatched a set of
-- credentials. As the sockets in NSE are limited we want to limit the risk of
-- a thread blocking, due to insufficient free sockets, after it has aquired a
-- username and password pair.
--
-- The following sample code illustrates how to implement a sample
-- <code>Driver</code> that sends each username and password over a socket.
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
--			return self.socket:connect( self.host, self.port )
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
-- The following sample code illustrates how to pass the <code>Driver</code>
-- off to the brute engine.
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
-- <code>svn-brute.nse</code> or <code>vnc-brute.nse</code> scripts
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
--
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
-- @args brute.mode can be user, pass or creds and determines what mode to run
--       the engine in.
--       * user - the unpwdb library is used to guess passwords, every password
--                password is tried for each user. (The user iterator is in the
--                outer loop)
--       * pass - the unpwdb library is used to guess passwords, each password
--                is tried for every user. (The password iterator is in the
--                outer loop)
--       * creds- a set of credentials (username and password pairs) are
--                guessed against the service. This allows for lists of known
--                or common username and password combinations to be tested.
--		 If no mode is specified and the script has not added any custom
--       iterator the pass mode will be enabled.
-- @args brute.credfile a file containing username and password pairs delimited
--       by '/'

--
-- Version 0.6
-- Created 06/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/13/2010 - v0.2 - added connect, disconnect methods to Driver
--							   <patrik@cqure.net>
-- Revised 07/21/2010 - v0.3 - documented missing argument brute.mode
-- Revised 07/23/2010 - v0.4 - fixed incorrect statistics and changed output to 
--							   include statistics, and to display "no accounts
--							   found" message.
-- Revised 08/14/2010 - v0.5 - added some documentation and smaller changes per
--                             David's request.
-- Revised 08/30/2010 - v0.6 - added support for custom iterators and did some
--                             needed cleanup.

module(... or "brute", package.seeall)
require 'unpwdb'
require 'datafiles'

-- Options that can be set through --script-args
Options = {
	
	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self

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

		if ( not(val) ) then return default end
		return ( val == "true" or val=="1" ) and true or false
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
	setOption = function( self, param, value ) self[param] = value end,

}

-- The account object which is to be reported back from each driver
Account =
{
	--- Creates a new instance of the Account class
	--
	-- @param username containing the user's name
	-- @param password containing the user's password
	-- @param state containing the account state and should be one of the
	--        following <code>OPEN</code>, <code>LOCKED</code>,
	--        <code>DISABLED</code>.
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
			creds = ("%s"):format( ( self.password and #self.password > 0 ) and self.password or "<empty>" )
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
	--
	-- @return status true if the error is recoverable, false if not
	isRetry = function( self ) return self.retry end,
	
	--- Set the error as recoverable
	--
	-- @param r boolean true if the engine should attempt to retry the
	--        credentials, unset or false if not
	setRetry = function( self, r ) self.retry = r end,
	
	--- Set the error as abort all threads
	--
	-- @param b boolean true if the engine should abort guessing on all threads
	setAbort = function( self, b ) self.abort = b end,
	
	--- Was the error abortable
	--
	-- @return status true if the driver flagged the engine to abort
	isAbort = function( self ) return self.abort end,
	
	--- Get the error message reported
	--
	-- @return msg string containing the error message
	getMessage = function( self ) return self.msg end,
	
	--- Is the thread done?
	--
	-- @return status true if done, false if not
	isDone = function( self ) return self.done end,
	
	--- Signals the engine that the thread is done and should be terminated
	--
	-- @param b boolean true if done, unset or false if not
	setDone = function( self, b ) self.done = b end,
	
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
		o.iterators = {}
		o.error = nil
		o.tps = {}
		return o
	end,

	--- Adds an iterator to the list
	--
	-- @param iterator function to add to the list
	addIterator = function( self, iterator )
		table.insert( self.iterators, iterator )
	end,

	--- Sets the engine running mode
	--
	-- @param mode string, one of either "user", "creds" or "pass"
	setMode = function( self, mode )
		mode = ( mode == "user" or mode == "creds" or mode == "pass" ) and mode or nil
		assert(mode, ("Unsupported mode: (%s)"):format(mode))
	end,
	
	--- Limit the number of worker threads
	--
	-- @param max number containing the maximum number of allowed threads
	setMaxThreads = function( self, max ) self.max_threads = max end,
			
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
			if ( v.guesses ~= nil ) then count = count + 1 end
		end
		return count		
	end,
	
	--- Iterator wrapper used to iterate over all registered iterators
	--
	-- @return iterator function
	get_next_credential = function( self )
		local function next_credential ()
			local used_creds = {}
			-- iterate over all credential iterators
			for _, iter in ipairs( self.iterators ) do
				for user, pass in iter do
					-- makes sure the credentials have not been tested before
					if ( not(used_creds[user..pass]) ) then
						used_creds[user..pass] = true
						coroutine.yield( user, pass )
					end
				end
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap( next_credential )
	end,
	
	--- Does the actual authentication request
	--
	-- @return true on success, false on failure
	-- @return response Account on success, Error on failure
	doAuthenticate = function( self )

		local status, response
		local next_credential = self:get_next_credential()
		local retries = self.options.max_retries
		
		repeat
			local driver = self.driver:new( self.host, self.port, self.driver_options )
			status = driver:connect()

			-- Did we succesfully connect?
			if ( status ) then

				local username, password
				if ( not(username) and not(password) ) then
					username, password = next_credential()
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
				
				local creds
				-- Do we have a username or not?
				if ( username and #username > 0 ) then
					creds = ("%s/%s"):format(username, #password > 0 and password or "<empty>")
				else
					creds = ("%s"):format(#password > 0 and password or "<empty>")
				end
			
				local msg = ( retries ~= self.options.max_retries ) and "Re-trying" or "Trying"
				stdnse.print_debug(2, "%s %s against %s:%d", msg, creds, self.host.ip, self.port.number )
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

		local condvar = nmap.condvar( valid_accounts )		
		local thread_data = self.threads[coroutine.running()]
		local interval_start = os.time()
		
		while( true ) do
			-- Should we terminate all threads?
			if ( Engine.terminate_all or thread_data.terminate ) then break	end
			
			local status, response = self:doAuthenticate()
				
			if ( status ) then
				-- Prevent locked accounts from appearing several times
				if ( not(self.found_accounts) or self.found_accounts[response.username] == nil ) then
					stdnse.print_debug("Discovered account: %s", response:toString())
					table.insert( valid_accounts, response:toString() )
					self.found_accounts[response.username] = true
					
					-- Check if firstonly option was set, if so abort all threads
					if ( self.options.firstonly ) then Engine.terminate_all = true end
				end
			else
				if ( response and response:isAbort() ) then
					Engine.terminate_all = true
					self.error = response:getMessage()
					break
				elseif( response and response:isDone() ) then
					break
				end
			end
				
			-- Increase the amount of total guesses
			self.counter = self.counter + 1
			local timediff = (os.time() - interval_start)
	
			-- This thread made another guess
			thread_data.guesses = ( thread_data.guesses and thread_data.guesses + 1 or 1 )

			-- Dump statistics at regular intervals
			if ( timediff > Engine.STAT_INTERVAL ) then
				interval_start = os.time()
				local tps = self.counter / ( os.time() - self.starttime )
				table.insert(self.tps, tps )
				stdnse.print_debug(2, "threads=%d,tps=%d", self:activeThreads(), tps )
			end

			-- if delay was speciefied, do sleep
			if ( self.options.delay > 0 ) then stdnse.sleep( self.options.delay ) end
		end
		condvar("broadcast")
	end,
			
	--- Starts the brute-force
	--
	-- @return status true on success, false on failure
	-- @return err string containing error message on failure
	start = function(self)
	
		local result, valid_accounts, stats = {}, {}, {}
		local condvar = nmap.condvar( valid_accounts )
		
		-- Only run the check method if it exist. We should phase this out
		-- in favor of a check in the action function of the script
		if ( self.driver:new( self.host, self.port, self.driver_options ).check ) then
			-- check if the driver is ready!
			local status, response = self.driver:new( self.host, self.port, self.driver_options ):check()
			if( not(status) ) then return false, response end
		end
		
		local status, usernames = unpwdb.usernames()
		if ( not(status) ) then	return false, "Failed to load usernames" end

		-- make sure we have a valid pw file
		local status, passwords = unpwdb.passwords()
		if ( not(status) ) then	return false, "Failed to load passwords" end
	
		local mode = stdnse.get_script_args("brute.mode")
	
		-- Are we guessing against a service that has no username (eg. VNC)
		if ( self.options.passonly ) then
			local function single_user_iter(next)
				local function next_user() coroutine.yield( "" ) end
				return coroutine.wrap(next_user)
			end
			table.insert( self.iterators, Iterators.user_pw_iterator( single_user_iter(), passwords ) )
		elseif ( mode == 'creds' ) then
			local credfile = stdnse.get_script_args("brute.credfile")
			if ( not(credfile) ) then
				return false, "No credential file specified"
			end
		
			local f = io.open( credfile, "r" )
			if ( not(f) ) then
				return false, ("Failed to open credfile (%s)"):format(credfile)
			end
			local creds = {}
			for line in f:lines() do
				local trim = function(s) return s:match('^()%s*$') and '' or s:match('^%s*(.*%S)') end 
				line = trim(line)
				local user, pass = line:match("^([^%/]*)%/(.*)$")
				table.insert(creds, { [user]=pass } )
			end
		
			table.insert( self.iterators, Iterators.credential_iterator( creds ) )
		elseif ( mode and mode == 'user' ) then
			table.insert( self.iterators, Iterators.user_pw_iterator( usernames, passwords ) )
		elseif( mode and mode == 'pass' ) then
			table.insert( self.iterators, Iterators.pw_user_iterator( usernames, passwords ) )
		elseif ( mode ) then
			return false, ("Unsupported mode: %s"):format(nmap.registry.args['brute.mode'])
		-- Default to the pw_user_iterator in case no iterator was specified
		elseif ( 0 == #self.iterators ) then
			table.insert( self.iterators, Iterators.pw_user_iterator( usernames, passwords ) )
		end

		self.starttime = os.time()

		-- Startup all worker threads
		for i=1, self.max_threads do
			local co = stdnse.new_thread( self.login, self, valid_accounts )
			self.threads[co] = {}
			self.threads[co].running = true
		end

		-- wait for all threads to finnish running
		while self:threadCount()>0 do condvar("wait") end
		
		-- Did we find any accounts, if so, do formatting
		if ( #valid_accounts > 0 ) then
			valid_accounts.name = "Accounts"
			table.insert( result, valid_accounts )
		else
			table.insert( result, {"No valid accounts found", name="Accounts"} )
		end
		
		-- calculate the average tps
		local sum = 0
		for _, v in ipairs( self.tps ) do sum = sum + v	end
		local time_diff = ( os.time() - self.starttime )
		time_diff = ( time_diff == 0 ) and 1 or time_diff
		local tps = ( sum == 0 ) and ( self.counter / time_diff ) or ( sum / #self.tps )

		-- Add the statistics to the result
		table.insert(stats, ("Performed %d guesses in %d seconds, average tps: %d"):format( self.counter, time_diff, tps ) )
		stats.name = "Statistics"
		table.insert( result, stats )

		result = ( #result ) and stdnse.format_output( true, result ) or ""
		
		-- Did any error occure? If so add this to the result.
		if ( self.error ) then
			result = result .. ("  \n\n  ERROR: %s"):format( self.error )
			return false, result
		end
		return true, result
	end,
	
}

Iterators = {

	--- Iterates over each user and password
	--
	-- @param users table containing list of users
	-- @param pass table containing list of passwords
	-- @param mode string, should be either 'user' or 'pass' and controls
	--        whether the users or passwords are in the 'outer' loop
	-- @return function iterator
	account_iterator = function(users, pass, mode)		
		local function next_credential ()
			local outer, inner

			if ( mode == 'pass' ) then
				outer, inner = pass, users
			elseif ( mode == 'user' ) then
				outer, inner = users, pass
			else
				return
			end

			if ( 'table' == type(users) and 'table' == type(pass) ) then
				for _, o in ipairs(outer) do
					for _, i in ipairs(inner) do
						if ( mode == 'pass' ) then
							coroutine.yield( i, o )
						else
							coroutine.yield( o, i )
						end
					end
				end
			elseif ( 'function' == type(users) and 'function' == type(pass) ) then
				for o in outer do
					for i in inner do
						if ( mode == 'pass' ) then
							coroutine.yield( i, o )
						else
							coroutine.yield( o, i )
						end
					end
					inner("reset")
				end
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap( next_credential )	
	end,


	--- Try each password for each user (user in outer loop)
	--
	-- @param users table containing list of users
	-- @param pass table containing list of passwords
	-- @return function iterator
	user_pw_iterator = function( users, pass )
		return Iterators.account_iterator( users, pass, "user" )
	end,

	--- Try each user for each password (password in outer loop)
	--
	-- @param users table containing list of users
	-- @param pass table containing list of passwords
	-- @return function iterator
	pw_user_iterator = function( users, pass )
		return Iterators.account_iterator( users, pass, "pass" )
	end,

	--- An iterator that returns the username as password
	--
	-- @param users table containing list of users
	-- @param case string [optional] 'upper' or 'lower', specifies if user
	--        and password pairs should be case converted.
	-- @return function iterator
	pw_same_as_user_iterator = function( users, case )	
		local function next_credential ()
			for _, user in ipairs(users) do
				if ( case == 'upper' ) then
					coroutine.yield( user:upper(), user:upper() )
				elseif( case == 'lower' ) then
					coroutine.yield( user:lower(), user:lower() )
				else
					coroutine.yield( user, user )
				end	
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap( next_credential )
	end,

	--- An iterator that returns the username and uppercase password
	--
	-- @param users table containing list of users
	-- @param pass table containing list of passwords
	-- @param mode string, should be either 'user' or 'pass' and controls
	--        whether the users or passwords are in the 'outer' loop
	-- @return function iterator
	pw_ucase_iterator = function( users, passwords, mode )
		local function next_credential ()
			for user, pass in Iterators.account_iterator(users, passwords, mode) do
				coroutine.yield( user, pass:upper() )
			end
			while true do coroutine.yield(nil, nil) end
		end
		return coroutine.wrap( next_credential )
	end,
	
	--- Credential iterator (for default or known user/pass combinations)
	--
	-- @param creds table containing username/pass combinations
	--        the table should be of the following format
	--        { ["user"] = "pass", ["user2"] = "pass2" }
	-- @return function iterator
	credential_iterator = function( creds )
		local function next_credential ()
			for _, item in ipairs(creds) do
				for user, pass in pairs(item) do
					coroutine.yield( user, pass )
				end
			end
			while true do coroutine.yield( nil, nil ) end
		end
		return coroutine.wrap( next_credential )
	end,
		
	unpwdb_iterator = function( mode )
		local status, users, passwords

		status, users = unpwdb.usernames()
		if ( not(status) ) then return end
		
		status, passwords = unpwdb.passwords()
		if ( not(status) ) then return end
		
		return Iterators.account_iterator( users, passwords, mode )
	end,
	
}
