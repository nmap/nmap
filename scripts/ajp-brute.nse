local ajp = require "ajp"
local base64 = require "base64"
local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force passwords auditing against the Apache JServ protocol.
The Apache JServ Protocol is commonly used by web servers to communicate with
back-end Java application server containers.
]]

---
-- @usage
-- nmap -p 8009 <ip> --script ajp-brute 
--
-- @output
-- PORT     STATE SERVICE
-- 8009/tcp open  ajp13
-- | ajp-brute: 
-- |   Accounts
-- |     root:secret - Valid credentials
-- |   Statistics
-- |_    Performed 1946 guesses in 23 seconds, average tps: 82
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(8009, 'ajp13', 'tcp')

local arg_url = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

Driver = {
	
	new = function(self, host, port, options)
		local o = { host = host, 
					port = port, 
					options = options, 
					helper = ajp.Helper:new(host, port)
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self)
		return self.helper:connect()
	end,
	
	disconnect = function(self)
		return self.helper:close()
	end,
	
	login = function(self, user, pass)
		local headers = {
			["Authorization"] = ("Basic %s"):format(base64.enc(user .. ":" .. pass))
		}
		local status, response = self.helper:get(arg_url, headers)
		
		if ( not(status) ) then
			local err = brute.Error:new( response )
			err:setRetry( true )
			return false, err
		elseif( response.status ~= 401 ) then
			return true, brute.Account:new(user, pass, creds.State.VALID)
		end
		return false, brute.Error:new( "Incorrect password" )
	end,

}


action = function(host, port)

	local helper = ajp.Helper:new(host, port)
	if ( not(helper:connect()) ) then
		return fail("Failed to connect to server")
	end
	
	local status, response = helper:get(arg_url)
	if ( not(response.headers['www-authenticate']) ) then
		return "\n  URL does not require authentication"
	end

	local challenges = http.parse_www_authenticate(response.headers['www-authenticate'])
	local options = { scheme = nil }
	for _, challenge in ipairs(challenges or {}) do
		if ( challenge and challenge.scheme and challenge.scheme:lower() == "basic") then
			options.scheme = challenge.scheme:lower()
			break
		end
	end
	
	if ( not(options.scheme) ) then
		return fail("Could not find a supported authentication scheme")
	end
	
	local engine = brute.Engine:new(Driver, host, port )
	engine.options.script_name = SCRIPT_NAME
	
	local status, result = engine:start()
	if ( status ) then
		return result
	end
end
