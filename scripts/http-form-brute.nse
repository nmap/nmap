description = [[
Performs brute force password auditing against http form-based authentication.
]]

---
-- @usage
-- nmap --script http-form-brute -p 80 <host>
--
-- This script uses the unpwdb and brute libraries to perform password
-- guessing. Any successful guesses are stored in the nmap registry, under
-- the nmap.registry.credentials.http key for other scripts to use.
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp   open  http    syn-ack
-- | http-brute:  
-- |   Accounts
-- |     Patrik Karlsson:secret => Login correct
-- |   Statistics
-- |_    Perfomed 60023 guesses in 467 seconds, average tps: 138
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
-- @args http-form-brute.path points to the path protected by authentication
-- @args http-form-brute.hostname sets the host header in case of virtual 
--       hosting
-- @args http-form-brute.uservar sets the http-variable name that holds the
--		 username used to authenticate. A simple autodetection of this variable
--       is attempted.
-- @args http-form-brute.passvar sets the http-variable name that holds the
--		 password used to authenticate. A simple autodetection of this variable
--       is attempted.


--
-- Version 0.1
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'http'
require 'brute'

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local form_params = {}

Driver = {
	
	new = function(self, host, port, options)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = nmap.registry.args['http-form-brute.hostname'] or host
		o.port = port
		o.path = nmap.registry.args['http-form-brute.path']
		o.options = options
		return o
	end,
	
	connect = function( self )
		-- This will cause problems, as ther is no way for us to "reserve"
		-- a socket. We may end up here early with a set of credentials
		-- which won't be guessed until the end, due to socket exhaustion.
		return true
	end,
	
	login = function( self, username, password )
		-- we need to supply the no_cache directive, or else the http library
		-- incorrectly tells us that the authentication was successfull
		local response = http.post( self.host, self.port, self.path, { no_cache = true }, nil, { [self.options.uservar] = username, [self.options.passvar] = password } )

		-- We check whether the body was empty or that we have a body without our user- and pass-var
		if ( not( response.body ) or 
		   ( response.body and not( response.body:match("name=\"*" .. self.options.uservar ) and response.body:match("name=\"*" .. self.options.passvar ) ) ) ) then
		
			if ( not( nmap.registry['credentials'] ) ) then
				nmap.registry['credentials'] = {}
			end
			if ( not( nmap.registry.credentials['http'] ) ) then
				nmap.registry.credentials['http'] = {}
			end
			table.insert( nmap.registry.credentials.http, { username = username, password = password } )
			return true, brute.Account:new( username, password, "OPEN")
		end
		
		return false, brute.Error:new( "Incorrect password" )
	end,
	
	disconnect = function( self ) 
		return true
	end,
	
	check = function( self )
		local response = http.get( self.host, self.port, self.path )
				
		-- do a *very* simple check
		if ( response.status == 200 and response.body:match("type=\"password\"")) then
			return true
		end
		return false
	end,
	
}

--- Attempts to auto-detect known form-fields
--
local function detectFormFields( host, port, path )
	local response = http.get( host, port, path )	
	local user_field, pass_field
	
	if ( response.status == 200 ) then
		user_field = response.body:match("<input.-name=[\"]-([^\"]-[Uu][Ss][Ee][Rr].-)[\"].->")
		pass_field = response.body:match("<input.-name=[\"]-([Pp][Aa][Ss][Ss].-)[\"].->")

		if ( not(pass_field) ) then
			pass_field = response.body:match("<input.-name=[\"]-([^\"]-[Kk][Ee][Yy].-)[\"].->")
		end
	end
	
	return user_field, pass_field
end

action = function( host, port )
	local uservar = nmap.registry.args['http-form-brute.uservar']
	local passvar = nmap.registry.args['http-form-brute.passvar']
  	local path = nmap.registry.args['http-form-brute.path'] or "/"
	local status, result, engine, _

	if ( not(uservar) and not(passvar) ) then
		uservar, passvar = detectFormFields( host, port, path )
	elseif ( not(uservar) ) then
		uservar, _ = detectFormFields( host, port, path )
	elseif ( not(passvar) ) then
		_, passvar = detectFormFields( host, port, path )
	end
	if ( not( uservar ) ) then
		return "  \n  ERROR: No uservar was specified (see http-form-brute.uservar)"
	end
	if ( not( passvar ) ) then
		return "  \n  ERROR: No passvar was specified (see http-form-brute.passvar)"
	end
	
	if ( not(nmap.registry.args['http-form-brute.path']) ) then
		return "  \n  ERROR: No path was specified (see http-form-brute.path)"
	end

	engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
	-- there's a bug in http.lua that does not allow it to be called by
	-- multiple threads
	engine:setMaxThreads(1)
	status, result = engine:start()
		
	return result
end