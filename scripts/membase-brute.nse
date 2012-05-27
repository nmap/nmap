local brute = require "brute"
local creds = require "creds"
local membase = require "membase"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against Couchbase Membase servers.
]]

---
-- @usage
-- nmap -p 11211 --script membase-brute
--
-- @output
-- PORT      STATE SERVICE
-- 11211/tcp open  unknown
-- | membase-brute: 
-- |   Accounts
-- |     buckettest:toledo - Valid credentials
-- |   Statistics
-- |_    Performed 5000 guesses in 2 seconds, average tps: 2500
--
-- @args membase-brute.bucketname if specified, password guessing is performed
--       only against this bucket.
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service({11210,11211}, "couchbase-tap", "tcp")

local arg_bucketname = stdnse.get_script_args(SCRIPT_NAME..".bucketname")


Driver = {
	
	new = function(self, host, port, options)
		local o = { host = host, port = port, options = options }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self)
		self.helper = membase.Helper:new(self.host, self.port)
		return self.helper:connect()
	end,
	
	login = function(self, username, password)
		local status, response = self.helper:login(arg_bucketname or username, password)
		if ( not(status) and "Auth failure" == response ) then
			return false, brute.Error:new( "Incorrect password" )
		elseif ( not(status) ) then
			local err = brute.Error:new( response )
			err:setRetry( true )
			return false, err
		end
		return true, brute.Account:new( arg_bucketname or username, password, creds.State.VALID)			
	end,
	
	disconnect = function(self)
		return self.helper:close()
	end
	
}


local function fail(err) return ("\n  ERROR: %s"):format(err) end

local function getMechs(host, port)
	local helper = membase.Helper:new(host, port)
	local status, err = helper:connect()
	if ( not(status) ) then
		return false, "Failed to connect to server"
	end
	
	local status, response = helper:getSASLMechList()
	if ( not(status) ) then
		stdnse.print_debug(2, "%s: Received unexpected response: %s", SCRIPT_NAME, response)
		return false, "Received unexpected response"
	end
		
	helper:close()
	return true, response.mechs
end

action = function(host, port)

	local status, mechs = getMechs(host, port)
	
	if ( not(status) ) then
		return fail(mechs)
	end
	if ( not(mechs:match("PLAIN") ) ) then
		return fail("Unsupported SASL mechanism")
	end
	
	local result 
	local engine = brute.Engine:new(Driver, host, port )
	
	engine.options.script_name = SCRIPT_NAME
	engine.options.firstonly = true

	if ( arg_bucketname ) then
		engine.options:setOption( "passonly", true )
	end
	
	status, result = engine:start()
	return result
end
