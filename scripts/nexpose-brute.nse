local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

local openssl = stdnse.silent_require "openssl"

description=[[
Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1.1.  By default it only tries three guesses per username to avoid target account lockout.
]]

---
-- @usage
-- nmap --script nexpose-brute -p 3780 <ip>
--
-- @output
-- PORT     STATE SERVICE     REASON  VERSION
-- 3780/tcp open  ssl/nexpose syn-ack NeXpose NSC 0.6.4
-- | nexpose-brute: 
-- |   Accounts
-- |     nxadmin:nxadmin - Valid credentials
-- |   Statistics
-- |_    Performed 5 guesses in 1 seconds, average tps: 5
--
-- As the Nexpose application enforces account lockout after 4 incorrect login
-- attempts, the script performs only 3 guesses per default. This can be
-- altered by supplying the <code>brute.guesses</code> argument a different 
-- value or 0 (zero) to guess the whole dictionary.

author = "Vlatko Kosturjak"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(3780, "nexpose", "tcp")

Driver = 
{
	new = function (self, host, port)
		local o = { host = host, port = port }
		setmetatable (o,self)
		self.__index = self
		return o
	end,

	connect = function ( self )	return true	end,

	login = function( self, username, password )
		local postdata='<?xml version="1.0" encoding="UTF-8"?><LoginRequest sync-id="1" user-id="'..username..'" password="'..password..'"></LoginRequest>'
		local response = http.post( self.host, self.port, '/api/1.1/xml', { no_cache = true, header = { ["Content-Type"] = "text/xml" } }, nil, postdata )

		if (not(response)) then
			local err = brute.Error:new( "Couldn't send/receive HTTPS request" )
			err:setRetry( true )
			return false, err
		end

		if (response.body == nil or response.body:match('<LoginResponse.*success="0"')) then
			stdnse.print_debug(2, "nexpose-brute: Bad login: %s/%s", username, password)
			return false, brute.Error:new( "Bad login" )
		elseif (response.body:match('<LoginResponse.*success="1"')) then
			stdnse.print_debug(1, "nexpose-brute: Good login: %s/%s", username, password)
			return true, brute.Account:new(username, password, creds.State.VALID)
		end
		stdnse.print_debug(1, "nexpose-brute: WARNING: Unhandled response: %s", response.body)
		return false, brute.Error:new( "incorrect response from server" )
	end,

	disconnect = function( self ) return true end,
}

action = function(host, port)
	local engine = brute.Engine:new(Driver, host, port)
	engine.options.script_name = SCRIPT_NAME
	engine.options.max_guesses = tonumber(stdnse.get_script_args('brute.guesses')) or 3
	local status, result = engine:start()
	return result
end
