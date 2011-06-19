--- The credential class stores found credentials in the Nmap registry
--
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- Version 0.1
-- Created 2011/02/06 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
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
	-- @param port table containign the port
	setFilter = function( self, host, port )
		self.filter.host = host
		self.filter.port = port
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
				table.insert(new_tbl, v)
			elseif ( not(host) and ( port == v.port ) ) then
				table.insert(new_tbl, v)
			elseif ( ( host and ( h == host or h == host.ip ) ) and not(port) ) then
				table.insert(new_tbl, v)
			elseif ( ( host and ( h == host or h == host.ip ) ) and port.number == v.port ) then
				table.insert(new_tbl, v)
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
