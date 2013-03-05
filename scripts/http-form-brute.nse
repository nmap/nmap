local brute = require "brute"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

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
-- The script automatically attempts to discover the form field names to
-- use in order to perform password guessing. If it fails doing so the form
-- parameters can be supplied using the uservar and passvar arguments.
--
-- After attempting to authenticate using a HTTP POST request the script
-- analyzes the response and attempt to determine whether authentication was
-- successful or not. The script analyzes this by checking the response using
-- the following rules:
--		1. If the response was empty the authentication was successful
--		2. If the response contains the message passed in the onsuccess
--		   argument the authentication was successful
--		3. If no onsuccess argument was passed, and if the response
--		   does not contain the message passed in the onfailure argument the
--		   authentication was successful
--		4. If neither the onsuccess or onfailure argument was passed and the
--		   response does not contain a password form field authentication
--		   was successful
--		5. Authentication failed
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
-- @args http-form-brute.uservar (optional) sets the http-variable name that
--       holds the username used to authenticate. A simple autodetection of
--       this variable is attempted.
-- @args http-form-brute.passvar sets the http-variable name that holds the
--		 password used to authenticate. A simple autodetection of this variable
--       is attempted.
-- @args http-form-brute.onsuccess (optional) sets the message to expect on
--		 successful authentication
-- @args http-form-brute.onfailure (optional) sets the message to expect on
--		 unsuccessful authentication

--
-- Version 0.3
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 05/23/2011 - v0.2 - changed so that uservar is optional
-- Revised 06/05/2011 - v0.3 - major re-write, added onsucces, onfailure and
--								support for redirects
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local form_params = {}

Driver = {
	
	new = function(self, host, port, options)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = nmap.registry.args['http-form-brute.hostname'] or host
		o.port = port
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
		local postparams = { [self.options.passvar] = password }
		if ( self.options.uservar ) then postparams[self.options.uservar] = username end
		
		local response = Driver.postRequest(self.host, self.port, self.options.path, postparams)
		local success = false
		
		-- if we have no response, we were successful
		if ( not(response.body) ) then
			success = true
		-- if we have a response and it matches our onsuccess match, login was successful
		elseif ( response.body and
				self.options.onsuccess and 
				response.body:match(self.options.onsuccess) ) then
			success = true
		-- if we have a response and it does not match our onfailure, login was successful
		elseif ( response.body and
				not(self.options.onsuccess) and
				self.options.onfailure and
				not(response.body:match(self.options.onfailure))) then
			success = true
		-- if we have a response and no onfailure or onsuccess match defined 
		-- and can't find a password field, login was successful
		elseif ( response.body and
				not(self.options.onfailure) and
				not(self.options.onsuccess) and
				not(response.body:match("input.-type=[\"]*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"]*"))
				) then
			success = true
		end

		-- We check whether the body was empty or that we have a body without our user- and pass-var
		if ( success ) then
			nmap.registry['credentials'] = nmap.registry['credentials'] or {}
			nmap.registry.credentials['http'] = nmap.registry.credentials['http'] or {}
			table.insert( nmap.registry.credentials.http, { username = username, password = password } )
			return true, brute.Account:new( username, password, creds.State.VALID)
		end
		
		return false, brute.Error:new( "Incorrect password" )
	end,
	
	disconnect = function( self ) 
		return true
	end,
	
	check = function( self )
		return true
	end,
	
	postRequest = function( host, port, path, options )
		local response = http.post( host, port, path, { no_cache = true }, nil, options )
		local status = ( response and tonumber(response.status) ) or 0
		if ( status > 300 and status < 400 ) then
			local new_path = url.absolute(path, response.header.location)
			response = http.get( host, port, new_path, { no_cache = true } )
		end
		return response
	end,
		
}

--- Attempts to auto-detect known form-fields
--
local function detectFormFields( host, port, path )
	local response = http.get( host, port, path )	
	local user_field, pass_field
	
	if ( response.status == 200 ) then
		user_field = response.body:match("<[Ii][Nn][Pp][Uu][Tt].-name=[\"]*([^\"]-[Uu][Ss][Ee][Rr].-)[\"]*.->")
		pass_field = response.body:match("<[Ii][Nn][Pp][Uu][Tt].-name=[\"]*([Pp][Aa][Ss][Ss].-)[\"]*.->")

		if ( not(pass_field) ) then
			pass_field = response.body:match("<[Ii][Nn][Pp][Uu][Tt].-name=[\"]-([^\"]-[Kk][Ee][Yy].-)[\"].->")
		end
	end
	
	return user_field, pass_field
end

action = function( host, port )
	local uservar = stdnse.get_script_args('http-form-brute.uservar')
	local passvar = stdnse.get_script_args('http-form-brute.passvar')
  	local path = stdnse.get_script_args('http-form-brute.path') or "/"
	local onsuccess = stdnse.get_script_args("http-form-brute.onsuccess")
	local onfailure = stdnse.get_script_args("http-form-brute.onfailure")
	
	local _

	-- if now fields were given attempt to autodetect
	if ( not(uservar) and not(passvar) ) then
		uservar, passvar = detectFormFields( host, port, path )
	-- if now passvar was detected attempt to autodetect
	elseif ( not(passvar) ) then
		_, passvar = detectFormFields( host, port, path )
	end
	
	-- uservar is optional, so only make sure we have a passvar
	if ( not( passvar ) ) then
		return "\n  ERROR: No passvar was specified (see http-form-brute.passvar)"
	end
	
	if ( not(path) ) then
		return "\n  ERROR: No path was specified (see http-form-brute.path)"
	end
	
	if ( onsuccess and onfailure ) then
		return "\n  ERROR: Either the onsuccess or onfailure argument should be passed, not both."
	end
	
	local options = { [passvar] = "this_is_not_a_valid_password" }
	if ( uservar ) then options[uservar] = "this_is_not_a_valid_user" end
	
	local response = Driver.postRequest( host, port, path, options )
	if ( not(response) or not(response.body) or response.status ~= 200 ) then
		return ("\n  ERROR: Failed to retrieve path (%s) from server"):format(path)
	end
	
	-- try to detect onfailure match
	if ( onfailure and not(response.body:match(onfailure)) ) then
		return ("\n  ERROR: Failed to match password failure message (%s)"):format(onfailure)
	elseif ( not(onfailure) and 
			not(onsuccess) and 
			not(response.body:match("input.-type=[\"]*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"]*")) ) then
		return ("\n  ERROR: Failed to detect password form field see (http-form-brute.onsuccess or http-form-brute.onfailure)")
	end
	
	local engine = brute.Engine:new( Driver, host, port, {
		uservar = uservar, passvar = passvar, 
		path = path, onsuccess = onsuccess, onfailure = onfailure
		} 
	)
	-- there's a bug in http.lua that does not allow it to be called by
	-- multiple threads
	engine:setMaxThreads(1)
	engine.options.script_name = SCRIPT_NAME
	
	if ( not(uservar) ) then
		engine.options:setOption( "passonly", true )
	end
	local status, result = engine:start()
		
	return result
end
