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
-- 	for _, cred in pairs(c:getCredentials(creds.State.VALID)) do
--		chowContentForUser(cred.user, cred.pass)
-- 	end
-- </code>
--

--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- Version 0.1
-- Created 2011/02/06 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2011/27/06 - v0.2 - revised by Patrik Karlsson <patrik@cqure.net>
--								added documentation
--								added getCredentials function
--

module(... or "creds", package.seeall)

require('ipOps')

-- Table containing the different account states
State = {
	LOCKED = { msg = 'Account is locked' },
	VALID = { msg = 'Account is valid' },
	DISABLED = { msg = 'Account is disabled' },
	CHANGEPW = { msg = 'Password needs to be changed at next logon' },
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
	
	--- Retrieves the table containing all credential records
	--
	-- @return table containing all credential records
	getAll = function( self )
		local tbl = nmap.registry.creds
		local new_tbl = {}
		local host, port = self.filter.host, self.filter.port

		if ( not(tbl) ) then return end
		
		for _, v in pairs(tbl) do
			local h = ( v.host.ip or v.host )
			if ( not(host) and not(port) ) then
				if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
					table.insert(new_tbl, v) 
				end
			elseif ( not(host) and ( port == v.port ) ) then
				if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
					table.insert(new_tbl, v) 
				end
			elseif ( ( host and ( h == host or h == host.ip ) ) and not(port) ) then
				if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
					table.insert(new_tbl, v) 
				end
			elseif ( ( host and ( h == host or h == host.ip ) ) and port.number == v.port ) then
				if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then 
					table.insert(new_tbl, v) 
				end
			end
		end
		return new_tbl
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
	-- @param host host table, name or ip
	-- @param port number containing the port of the service
	-- @param service the name of the service
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
	
	--- Returns all accounts for a given state, or all states if no filter is set
	--
	-- @param state table containing a value from the <Code>State</code> table
	-- @return table containing accounts matching the state, or all accounts if
	--         no state was given. Accounts have the following fields:
	--         <code>host</code> - table as received by the action function
	--         <code>port</code> - number containing the port number
	--         <code>user</code> - string containing the user name
	--         <code>pass</code> - string containing the user password
	--         <code>state</code> - a state table @see <code>State</code>
	--         <code>service</code> - string containing the name of the service
	--         <code>scriptname</code> - string containing the name of the
	--                                   script that added the credential
	getCredentials = function(self, state)
		if ( state ) then 
			self.storage:setFilter(self.host, { number=self.port, service = self.service }, state)
		end
		return self.storage:getAll()
	end,
	
	--- Returns a table of credentials
	--
	-- @return tbl table containing the discovered credentials	
	getTable = function(self)
		local result = {}
		local all = self.storage:getAll()
		
		if ( not(all) ) then return end

		for _, v in pairs(self.storage:getAll()) do
			local h = ( v.host.ip or v.host )
			local svc = ("%s/%s"):format(v.port,v.service)
			local c 
			if ( v.user and #v.user > 0 ) then
				c = ("%s:%s - %s"):format(v.user, v.pass, v.state.msg)
			else
				c = ("%s - %s"):format(v.pass, v.state.msg)
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
		return output
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
