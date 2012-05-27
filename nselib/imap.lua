---
-- A library implementing a minor subset of the IMAP protocol, currently the
-- CAPABILITY, LOGIN and AUTHENTICATE functions. The library was initially
-- written by Brandon Enright and later extended and converted to OO-form by
-- Patrik Karlsson <patrik@cqure.net>
--
-- The library consists of a <code>Helper</code>, class which is the main
-- interface for script writers, and the <code>IMAP</code> class providing
-- all protocol-level functionality.
--
-- The following example illustrates the reommended use of the library:
-- <code>
-- 	local helper = imap.Helper:new(host, port)
--  helper:connect()
--  helper:login("user","password","PLAIN")
--  helper:close()
-- </code>
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author = "Brandon Enright, Patrik Karlsson"

-- Version 0.2
-- Revised 07/15/2011 - v0.2 - 	added the IMAP and Helper classes
--								added support for LOGIN and AUTHENTICATE
--								<patrik@cqure.net>

local base64 = require "base64"
local comm = require "comm"
local sasl = require "sasl"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("imap", stdnse.seeall)


IMAP = {
	
	--- Creates a new instance of the IMAP class
	--
	-- @param host table as received by the script action method
	-- @param port table as received by the script action method
	-- @param options table containing options, currently
	--		<code>timeout<code> - 	number containing the seconds to wait for
	--								a response
	new = function(self, host, port, options)
		local o = { 
				host = host,
				port = port,
				counter = 1, 
				timeout = ( options and options.timeout ) or 10000 
		}
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	--- Receives a response from the IMAP server
	--
	-- @return status true on success, false on failure
	-- @return data string containing the received data
	receive = function(self)
		local data = ""
		repeat
			local status, tmp = self.socket:receive_buf("\r\n", false)
			if( not(status) ) then return false, tmp end
			data = data .. tmp
		until( tmp:match(("^A%04d"):format(self.counter - 1)) or tmp:match("^%+"))
		
		return true, data
	end,
	
	--- Sends a request to the IMAP server
	--
	-- @param cmd string containing the command to send to the server eg.
	--            eg. (AUTHENTICATE, LOGIN)
	-- @param params string containing the command parameters
	-- @return true on success, false on failure
	-- @return err string containing the error if status was false
	send = function(self, cmd, params)
		local data
		if ( not(params) ) then
			data = ("A%04d %s\r\n"):format(self.counter, cmd)
		else
			data = ("A%04d %s %s\r\n"):format(self.counter, cmd, params)
		end
		local status, err = self.socket:send(data)
		if ( not(status) ) then return false, err end
		self.counter = self.counter + 1
		return true
	end,
	
	--- Connect to the server
	--
	-- @return status true on success, false on failure
	-- @return banner string containing the server banner
	connect = function(self)
		local socket, banner, opt = comm.tryssl( self.host, self.port, "", { recv_before = true } )
		if ( not(socket) ) then return false, "ERROR: Failed to connect to server" end
		socket:set_timeout(self.timeout)
		if ( not(socket) or not(banner) ) then return false, "ERROR: Failed to connect to server" end
		self.socket = socket
		return true, banner
	end,
		
	--- Authenticate to the server (non PLAIN text mode)
	-- Currently supported algorithms are CRAM-MD5 and CRAM-SHA1
	--
	-- @param username string containing the username
	-- @param pass string containing the password
	-- @param mech string containing a authentication mechanism, currently
	--				CRAM-MD5 or CRAM-SHA1
	-- @return status true if login was successful, false on failure
	-- @return err string containing the error message if status was false
	authenticate = function(self, username, pass, mech)
		assert( mech == "NTLM" or
				mech == "DIGEST-MD5" or
				mech == "CRAM-MD5" or 
				mech == "PLAIN",
				"Unsupported authentication mechanism")
		
		local status, err = self:send("AUTHENTICATE", mech)

		if( not(status) ) then return false, "ERROR: Failed to send data" end

		local status, data = self:receive()
		if( not(status) ) then return false, "ERROR: Failed to receive challenge" end
		
		if ( mech == "NTLM" ) then
			-- sniffed of the wire, seems to always be the same
			-- decodes to some NTLMSSP blob greatness
			status, data = self.socket:send("TlRMTVNTUAABAAAAB7IIogYABgA3AAAADwAPACgAAAAFASgKAAAAD0FCVVNFLUFJUi5MT0NBTERPTUFJTg==\r\n")
			if ( not(status) ) then return false, "ERROR: Failed to send NTLM packet" end
			status, data = self:receive()
			if ( not(status) ) then return false, "ERROR: Failed to receieve NTLM challenge" end 
		end
		
		if ( data:match(("^A%04d "):format(self.counter-1)) ) then
			return false, "ERROR: Authentication mechanism not supported"
		end

		local digest, auth_data
		if ( not(data:match("^+")) ) then
			return false, "ERROR: Failed to receive proper response from server"
		end
		data = base64.dec(data:match("^+ (.*)"))
		
		-- All mechanisms expect username and pass
		-- add the otheronce for those who need them
		local mech_params = { username, pass, data, "imap" }
		auth_data = sasl.Helper:new(mech):encode(table.unpack(mech_params))
		auth_data = base64.enc(auth_data) .. "\r\n"
			
		status, data = self.socket:send(auth_data)
		if( not(status) ) then return false, "ERROR: Failed to send data" end

		status, data = self:receive()
		if( not(status) ) then return false, "ERROR: Failed to receive data" end
	
		if ( mech == "DIGEST-MD5" ) then
			local rspauth = data:match("^+ (.*)")
			if ( rspauth ) then
				rspauth = base64.dec(rspauth)
				status, data = self.socket:send("\r\n")
				status, data = self:receive()
			end
		end
		if ( data:match(("^A%04d OK"):format(self.counter - 1)) ) then
			return true
		end
		return false, "Login failed"
	end,
	
	--- Login to the server using PLAIN text authentication
	--
	-- @param username string containing the username
	-- @param password string containing the password
	-- @return status true on success, false on failure
	-- @return err string containing the error message if status was false
	login = function(self, username, password)
		local status, err = self:send("LOGIN", ("\"%s\" \"%s\""):format(username, password))
		if( not(status) ) then return false, "ERROR: Failed to send data" end
		
		local status, data = self:receive()
		if( not(status) ) then return false, "ERROR: Failed to receive data" end
			
		if ( data:match(("^A%04d OK"):format(self.counter - 1)) ) then
			return true
		end
		return false, "Login failed"
	end,
	
	--- Retrieves a list of server capabilities (eg. supported authentication
	--  mechanisms, QUOTA, UIDPLUS, ACL ...)
	--
	-- @return status true on success, false on failure
	-- @return capas array containing the capabilities that are supported
	capabilities = function(self)
		local capas = {}
		local proto = (self.port.version and self.port.version.service_tunnel == "ssl" and "ssl") or "tcp"
		local status, err = self:send("CAPABILITY")
		if( not(status) ) then return false, err end
	   
		local status, line = self:receive()
		if (not(status)) then
			capas.CAPABILITY = false
		else 
			while status do
				if ( line:match("^%*%s+CAPABILITY") ) then
		    		line = line:gsub("^%*%s+CAPABILITY", "")
					for capability in line:gmatch("[%w%+=-]+") do
						capas[capability] = true
	            	end
	            	break
				end
				status, line = self.socket:receive()
			end
	   end
	   return true, capas
	end,
	
	--- Closes the connection to the IMAP server
	-- @return true on success, false on failure
	close = function(self) return self.socket:close() end
	
}


-- The helper class, that servers as interface to script writers
Helper = {
	
	-- @param host table as received by the script action method
	-- @param port table as received by the script action method
	-- @param options table containing options, currently
	--		<code>timeout<code> - 	number containing the seconds to wait for
	--								a response
	new = function(self, host, port, options)
		local o = { client = IMAP:new( host, port, options ) }
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	--- Connects to the IMAP server
	-- @return status true on success, false on failure
	connect = function(self)
		return self.client:connect()
	end,
	
	--- Login to the server using eithe plain-text or using the authentication
	-- mechanism provided in the mech argument.
	--
	-- @param username string containing the username
	-- @param password string containing the password
	-- @param mech [optional] containing the authentication mechanism to use
	-- @return status true on success, false on failure
	login = function(self, username, password, mech)
		if ( not(mech) or mech == "LOGIN" ) then
			return self.client:login(username, password)
		else
			return self.client:authenticate(username, password, mech)
		end
	end,
	
	--- Retrieves a list of server capabilities (eg. supported authentication
	--  mechanisms, QUOTA, UIDPLUS, ACL ...)
	--
	-- @return status true on success, false on failure
	-- @return capas array containing the capabilities that are supported
	capabilities = function(self)
		return self.client:capabilities()
	end,
	
	--- Closes the connection to the IMAP server
	-- @return true on success, false on failure
	close = function(self)
		return self.client:close()
	end,
	
}

return _ENV;
