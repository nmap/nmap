local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd).
]]

---
-- @usage
-- nmap -p 902 <ip> --script vmauthd-brute
--
-- @output
-- PORT    STATE SERVICE
-- 902/tcp open  iss-realsecure
-- | vmauthd-brute: 
-- |   Accounts
-- |     root:00000 - Valid credentials
-- |   Statistics
-- |_    Performed 183 guesses in 40 seconds, average tps: 4
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


portrule = shortport.port_or_service(902, {"ssl/vmware-auth", "vmware-auth"}, "tcp")

local function fail(err) return ("\n  ERROR: %s"):format(err) end

Driver = {
	
	new = function(self, host, port, options)
		local o = { host = host, port = port }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self)
		self.socket = nmap.new_socket()
		return self.socket:connect(self.host, self.port)
	end,
	
	login = function(self, username, password)
		local status, line = self.socket:receive_buf("\r\n", false)
		if ( line:match("^220 VMware Authentication Daemon.*SSL Required") ) then
			self.socket:reconnect_ssl()
		end

		status = self.socket:send( ("USER %s\r\n"):format(username) )
		if ( not(status) ) then
			local err = brute.Error:new( "Failed to send data to server" )
			err:setRetry( true )
			return false, err
		end
		
		local status, response = self.socket:receive_buf("\r\n", false)
		if ( not(status) or not(response:match("^331") ) ) then
			local err = brute.Error:new( "Received unexpected response from server" )
			err:setRetry( true )
			return false, err
		end

		status = self.socket:send( ("PASS %s\r\n"):format(password) )
		if ( not(status) ) then
			local err = brute.Error:new( "Failed to send data to server" )
			err:setRetry( true )
			return false, err
		end
		status, response = self.socket:receive_buf("\r\n", false)

		if ( response:match("^230") ) then
			return true, brute.Account:new(username, password, creds.State.VALID)
		end
		
		return false, brute.Error:new( "Login incorrect" )
	end,
	
	disconnect = function(self)
		return self.socket:close()
	end
	
}

local function checkAuthd(host, port)	
	local socket = nmap.new_socket()
	local status = socket:connect(host, port)
	
	if( not(status) ) then
		return false, "Failed to connect to server"
	end

	local status, line = socket:receive_buf("\r\n", false)
	socket:close()
	if ( not(status) ) then
		return false, "Failed to receive response from server"
	end

	if ( not( line:match("^220 VMware Authentication Daemon") ) ) then
		return false, "Failed to detect VMWare Authentication Daemon"
	end
	return true
end


action = function(host, port)
	local status, err = checkAuthd(host, port)
	if ( not(status) ) then
		return fail(err)
	end

	local engine = brute.Engine:new(Driver, host, port)
	engine.options.script_name = SCRIPT_NAME
	local result
	status, result = engine:start()
	return result
end
