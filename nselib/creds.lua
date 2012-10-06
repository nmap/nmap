--- The credential class stores found credentials in the Nmap registry
--
-- The credentials library may be used by scripts to store credentials in
-- a common format in the nmap registry. The Credentials class serves as
-- a primary interface for scripts to the library.
--
-- The State table keeps track of possible account states and a corresponding
-- message to return for each state.
--
-- The following code illustrates how a script may add discovered credentials
-- to the database:
-- <code>
-- 	local c = creds.Credentials:new( SCRIPT_NAME, host, port )
-- 	c:add("patrik", "secret", creds.State.VALID )
-- </code>
--
-- The following code illustrates how a script can return a table of discovered
-- credentials at the end of execution:
-- <code>
--	return tostring(creds.Credentials:new(SCRIPT_NAME, host, port))
-- </code>
--
-- The following code illustrates how a script may iterate over discovered
-- credentials:
-- <code>
--	local c = creds.Credentials:new(creds.ALL_DATA, host, port)
-- 	for cred in c:getCredentials(creds.State.VALID) do
--		showContentForUser(cred.user, cred.pass)
-- 	end
-- </code>
--
-- The library also enables users to add credentials through script arguments
-- either globally or per service. These credentials may be retrieved by script
-- through the same functions as any other discovered credentials. Arguments
-- passed using script arguments will be added with the PARAM state. The
-- following code may be used by a scripts to retrieve these credentials:
-- <code>
--	local c = creds.Credentials:new(creds.ALL_DATA, host, port)
--	for cred in c:getCredentials(creds.State.PARAM) do
--		... do something ...
--	end
-- </code>
--
-- Any globally added credentials will be made available to all scripts,
-- regardless of what service is being filtered through the host and port
-- arguments when instantiating the Credentials class. Service specific
-- arguments will only be made available to scripts with ports matching
-- the service name. The following two examples illustrate how credentials are
-- added globally and for the http service:
-- --script-args creds.global='admin:nimda'
-- --script-args creds.http='webadmin:password'
--
-- The service name at this point may be anything and the entry is created
-- dynamically without validating whether the service exists or not. 
--
-- The credential argument is not documented in this library using the <at>args
-- function as the argument would incorrectly show up in all scripts making use
-- of this library. This would show that credentials could be added to scripts
-- that do not make use of this function. Therefore any scripts that make use
-- of the credentials passing arguments need to have appropriate documentation
-- added to them.
--
--
-- The following code illustrates how a script may save its discovered credentials
-- to a file:
-- <code>
-- 	local c = creds.Credentials:new( SCRIPT_NAME, host, port )
-- 	c:add("patrik", "secret", creds.State.VALID )
--  status, err = c:saveToFile("outputname","csv")
-- </code>
--
--  Supported output formats are CSV, verbose and plain.  In both verbose and plain
--  records are seperated by colons.  The difference between the two is that verbose
--  includes the credential state.  The file extension is automatically added to 
--  the filename based on the type requested.
-- 
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- Version 0.4
-- Created 2011/02/06 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2011/27/06 - v0.2 - revised by Patrik Karlsson <patrik@cqure.net>
--								* added documentation
--								* added getCredentials function
--
-- Revised 2011/05/07 - v0.3 - revised by Patrik Karlsson <patrik@cqure.net>
--                              * modified getCredentials to return an iterator
--                              * added support for adding credentials as
--                                script arguments
--
-- Revised 2011/09/04 - v0.4 - revised by Tom Sellers
--                              * added saveToFile function for saving credential
--								* table to file in CSV or text formats

local bit = require "bit"
local coroutine = require "coroutine"
local io = require "io"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("creds", stdnse.seeall)


-- Table containing the different account states
State = {
	LOCKED = 1,
	VALID = 2,
	DISABLED = 4,
	CHANGEPW = 8,
	PARAM = 16,
	EXPIRED = 32,
	TIME_RESTRICTED = 64,
	HOST_RESTRICTED = 128,
	LOCKED_VALID = 256,
	DISABLED_VALID = 512,
	HASHED = 1024,
}

StateMsg = {
	[State.LOCKED]    = 'Account is locked',
	[State.VALID]     = 'Valid credentials',
	[State.DISABLED]  = 'Account is disabled',
	[State.CHANGEPW]  = 'Valid credentials, password must be changed at next logon',
	[State.PARAM]  = 'Credentials passed to script during Nmap execution',
	[State.EXPIRED]   = 'Valid credentials, account expired',
	[State.TIME_RESTRICTED] = 'Valid credentials, account cannot log in at current time',
	[State.HOST_RESTRICTED] = 'Valid credentials, account cannot log in from current host',
	[State.LOCKED_VALID]    = 'Valid credentials, account locked',
	[State.DISABLED_VALID]  = 'Valid credentials, account disabled',
	[State.HASHED]  = 'Hashed valid or invalid credentials',
}


ALL_DATA = "all_script_data"

-- The RegStorage class
RegStorage = {

	--- Creates a new RegStorage instance
	--
	-- @return a new instance
	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.filter = {}
		return o
	end,
	
	--- Add credentials to storage
	--
	-- @param scriptname the name of the script adding the credentials
	-- @param host host table, name or ip
	-- @param port number containing the port of the service
	-- @param service the name of the service
	-- @param user the name of the user
	-- @param pass the password of the user
	-- @param state of the account
	add = function( self, scriptname, host, port, service, user, pass, state )
		local cred = { 
			scriptname = scriptname,
			host = host,
			port = port,
			service = service,
			user = user,
			pass = pass,
			state = state
		}
		nmap.registry.creds = nmap.registry.creds or {}
		table.insert( nmap.registry.creds, cred )
	end,
	
	--- Sets the storage filter
	--
	-- @param host table containing the host
	-- @param port table containing the port
	-- @param state table containing the account state
	setFilter = function( self, host, port, state )
		self.filter.host = host
		self.filter.port = port
		self.filter.state = state
	end,
	
	--- Returns a credential iterator matching the selected filters
	--
	-- @return a credential iterator
	getAll = function( self )
		local function get_next()
			local host, port = self.filter.host, self.filter.port

			if ( not(nmap.registry.creds) ) then return end
		
			for _, v in pairs(nmap.registry.creds) do
				local h = ( v.host.ip or v.host )
				if ( not(host) and not(port) ) then
					if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
						coroutine.yield(v)
					end
				elseif ( not(host) and ( port == v.port ) ) then
					if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
						coroutine.yield(v)
					end
				elseif ( ( host and ( h == host or h == host.ip ) ) and not(port) ) then
					if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
						coroutine.yield(v)
					end
				elseif ( ( host and ( h == host or h == host.ip ) ) and port.number == v.port ) then
					if ( not(self.filter.state) or ( v.state == bit.band(self.filter.state, v.state) ) ) then 
						coroutine.yield(v)
					end
				end
			end
		end
		return coroutine.wrap(get_next)
	end,
	
}

-- The credentials class
Credentials = {
	
	--- Creates a new instance of the Credentials class
	-- @param scriptname string containing the name of the script
	-- @param host table as received by the scripts action method
	-- @param port table as received by the scripts action method
	new = function(self, scriptname, host, port)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.storage = RegStorage:new()
		o.storage:setFilter(host, port)
		o.host = host
		o.port = ( port and port.number ) and port.number 
		o.service = ( port and port.service ) and port.service
		o.scriptname = scriptname
		return o
	end,
	
	--- Add a discovered credential
	--
	-- @param user the name of the user
	-- @param pass the password of the user
	-- @param state of the account
	add = function( self, user, pass, state )
		local pass = ( pass and #pass > 0 ) and pass or "<empty>"
		assert( self.host, "No host supplied" )
		assert( self.port, "No port supplied" )
		assert( state, "No state supplied")
		assert( self.scriptname, "No scriptname supplied")

		-- there are cases where we will only get a user or password
		-- so as long we have one of them, we're good
		if ( user or pass ) then
			self.storage:add( self.scriptname, self.host, self.port, self.service, user, pass, state )
		end
	end,
	
	--- Returns a credential iterator
	--
	-- @param state mask containing values from the <Code>State</code> table
	-- @return credential iterator, returning a credential each time it's 
	--         called. Unless filtered by the state mask all credentials
	--         for the host, port match are iterated over.
	--         The credential table has the following fields:
	--         <code>host</code> - table as received by the action function
	--         <code>port</code> - number containing the port number
	--         <code>user</code> - string containing the user name
	--         <code>pass</code> - string containing the user password
	--         <code>state</code> - a state number @see <code>State</code>
	--         <code>service</code> - string containing the name of the service
	--         <code>scriptname</code> - string containing the name of the
	--                                   script that added the credential
	getCredentials = function(self, state)
		local function next_credential()
			if ( state ) then 
				self.storage:setFilter(self.host, { number=self.port, service = self.service }, state)
			end

			for cred in self.storage:getAll() do
				if ( ( self.scriptname == ALL_DATA ) or
					 ( cred.scriptname == self.scriptname ) ) then
					coroutine.yield(cred)
				end
			end

			if ( state and State.PARAM == bit.band(state, State.PARAM) ) then
				local creds_global = stdnse.get_script_args('creds.global')
				local creds_service
				local creds_params
				
				if ( self.service ) then
					creds_service = stdnse.get_script_args('creds.' .. self.service )
				end
				
				if ( creds_service ) then creds_params = creds_service end
				if ( creds_global and creds_service ) then
					creds_params = creds_params .. ',' .. creds_global
				elseif ( creds_global ) then
					creds_params = creds_global
				end

				if ( not(creds_params) ) then return end

				for _, cred in ipairs(stdnse.strsplit(",", creds_params)) do
					-- if the credential contains a ':' we have a user + pass pair
					-- if not, we only have a user with an empty password
					local user, pass
					if ( cred:match(":") ) then
						user, pass = cred:match("^(.-):(.-)$")
					else
						user = cred:match("^(.*)$")
					end
					coroutine.yield( { host = self.host, 
					port = self.port,
					user = user, 
					pass = pass,
					state = State.PARAM,
					service = self.service } )
				end
			end
		end
		return coroutine.wrap( next_credential )
	end,
	
	--- Returns a table of credentials
	--
	-- @return tbl table containing the discovered credentials	
	getTable = function(self)
		local result = {}

		for v in self.storage:getAll() do
			local h = ( v.host.ip or v.host )
			local svc = ("%s/%s"):format(v.port,v.service)
			local c
			if ( v.user and #v.user > 0 ) then
				if StateMsg[v.state] then
				        c = ("%s:%s - %s"):format(v.user, v.pass, StateMsg[v.state])
				else
				        c = ("%s:%s"):format(v.user, v.pass)
				end
			else
				if StateMsg[v.state] then
					c = ("%s - %s"):format(v.pass, StateMsg[v.state])
				else
					c = ("%s"):format(v.pass)
				end
			end
			local script = v.scriptname
			assert(type(h)=="string", "Could not determine a valid host")

			if ( script == self.scriptname or self.scriptname == ALL_DATA ) then
				result[h] = result[h] or {}
				result[h][svc] = result[h][svc] or {}
				table.insert( result[h][svc], c )
			end
		end
		
		local output = {}
		for hostname, host in pairs(result) do
			local host_tbl = { name = hostname }
			for svcname, service in pairs(host) do
				local svc_tbl = { name = svcname }
				for _, account in ipairs(service) do
					table.insert(svc_tbl, account)
				end
				-- sort the accounts
				table.sort( svc_tbl, function(a,b) return a<b end)
				table.insert( host_tbl, svc_tbl )
			end
			-- sort the services
			table.sort( host_tbl, 
			function(a,b)
				return tonumber(a.name:match("^(%d+)")) < tonumber(b.name:match("^(%d+)"))
			end
			)
			table.insert( output, host_tbl )
		end

		-- sort the IP addresses
		table.sort( output, function(a, b) return ipOps.compare_ip(a.name, "le", b.name) end )
		if ( self.host and self.port and #output > 0 ) then
			output = output[1][1]
			output.name = nil
		elseif ( self.host and #output > 0 ) then
			output = output[1]
			output.name = nil
		end
		return (#output > 0 ) and output
	end,
	
	-- Saves credentials in the current object to file
	-- @param filename string name of the file
	-- @param fileformat string file format type, values = csv | verbose | plain (default)
	-- @return status true on success, false on failure
	-- @return err string containing the error if status is false
	saveToFile = function(self, filename, fileformat)
	
		if ( fileformat == 'csv' ) then
			filename = filename .. '.csv'
		else
			filename = filename .. '.txt'
		end
	
		local f = io.open( filename, "w")
		local output = nil
		
		if ( not(f) ) then
			return false, ("ERROR: Failed to open file (%s)"):format(filename)
		end
	
		for account in self:getCredentials() do
			if ( fileformat == 'csv' ) then
				output = "\"" .. account.user .. "\",\"" .. account.pass .. "\",\"" .. StateMsg[account.state] .. "\""
			elseif ( fileformat == 'verbose') then
				output = account.user .. ":" .. account.pass .. ":" .. StateMsg[account.state]
			else
				output = account.user .. ":" .. account.pass
			end
			if ( not(f:write( output .."\n" ) ) ) then
				return false, ("ERROR: Failed to write file (%s)"):format(filename)
			end
		end

		f:close()
		return true
	end,
	
	--- Get credentials with optional host and port filter
	-- If no filters are supplied all records are returned
	--
	-- @param host table or string containing the host to filter
	-- @param port number containing the port to filter
	-- @return table suitable from <code>stdnse.format_output</code>
	__tostring = function(self)
		local all = self:getTable()
		if ( all ) then	return stdnse.format_output(true, all) end
	end,
	
}

return _ENV;
