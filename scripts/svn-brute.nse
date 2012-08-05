local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"

description = [[
Performs brute force password auditing against Subversion source code control servers.
]]

---
-- @usage
-- nmap --script svn-brute --script-args svn-brute.repo=/svn/ -p 3690 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 3690/tcp open  svn     syn-ack
-- | svn-brute:  
-- |   Accounts
-- |_    patrik:secret => Login correct
--
-- Summary
-- -------
--   x The svn class contains the code needed to perform CRAM-MD5
--     authentication
--   x The Driver class contains the driver implementation used by the brute
--     library
--
-- @args svn-brute.repo the Subversion repository against which to perform
--                      password guessing
-- @args svn-brute.force force password guessing when service is accessible
--       both anonymously and through authentication

--
-- Version 0.1
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(3690, "svnserve", "tcp", "open")

svn = 
{
	svn_client = "nmap-brute v0.1",
	
	new = function(self, host, port, repo)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.repo = repo
		o.invalid_users = {}
		return o
	end,

	--- Connects to the SVN - repository
	--
	-- @return status true on success, false on failure
	-- @return err string containing an error message on failure 
	connect = function(self)
		local repo_url = ( "svn://%s/%s" ):format(self.host.ip, self.repo)
		local status, msg
		
		self.socket = nmap.new_socket()

		local result
		status, result = self.socket:connect(self.host.ip, self.port.number, "tcp")
		if( not(status) ) then
			return false, result
		end
		
		status, msg = self.socket:receive_bytes(1)
		if ( not(status) or not( msg:match("^%( success") ) ) then
			return false, "Banner reports failure"
		end
		
		msg = ("( 2 ( edit-pipeline svndiff1 absent-entries depth mergeinfo log-revprops ) %d:%s %d:%s ( ) ) "):format( #repo_url, repo_url, #self.svn_client, self.svn_client )
		status = self.socket:send( msg )
		if ( not(status) ) then
			return false, "Send failed"
		end
	
		status, msg = self.socket:receive_bytes(1)
		if ( not(status) ) then
			return false, "Receive failed"
		end
		
		if ( msg:match("%( success") ) then
			local tmp = msg:match("%( success %( %( ([%S+%s*]-) %)")
			if ( not(tmp) ) then return false, "Failed to detect authentication" end
			tmp = stdnse.strsplit(" ", tmp)
			self.auth_mech = {}
			for _, v in pairs(tmp) do self.auth_mech[v] = true end
		elseif ( msg:match("%( failure") ) then
			return false
		end

		return true		
	end,
	
	--- Attempts to login to the SVN server
	--
	-- @param username string containing the login username
	-- @param password string containing the login password
	-- @return status, true on success, false on failure
	-- @return err string containing error message on failure
	login = function( self, username, password )
		local status, msg
		local challenge, digest
		
		if ( self.auth_mech["CRAM-MD5"] ) then
			msg = "( CRAM-MD5 ( ) ) "
			status = self.socket:send( msg )
		
			status, msg = self.socket:receive_bytes(1)
			if ( not(status) ) then
				return false, "error"
			end
		
			challenge = msg:match("<.+>")
		
			if ( not(challenge) ) then
				return false, "Failed to read challenge"
			end
		
			digest = stdnse.tohex(openssl.hmac('md5', password, challenge))
			msg = ("%d:%s %s "):format(#username + 1 + #digest, username, digest)
			self.socket:send( msg )
		
			status, msg = self.socket:receive_bytes(1)
			if ( not(status) ) then
				return false, "error"
			end
			
			if ( msg:match("Username not found") ) then
				return false, "Username not found"
			elseif ( msg:match("success") ) then
				return true, "Authentication success"
			else
				return false, "Authentication failed"
			end
		else
			return false, "Unsupported auth-mechanism"
		end
		
	end,
	
	--- Close the SVN connection
	--
	-- @return status true on success, false on failure
	close = function(self)
		return self.socket:close()
	end,
	
}


Driver =
{		
	new = function(self, host, port, invalid_users )
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.repo = stdnse.get_script_args('svn-brute.repo')
		o.invalid_users = invalid_users
		return o
	end,
	
	connect = function( self )
		local status, msg
		
		self.svn = svn:new( self.host, self.port, self.repo )
		status, msg = self.svn:connect()
		if ( not(status) ) then
			local err = brute.Error:new( "Failed to connect to SVN server" )
			-- This might be temporary, set the retry flag
			err:setRetry( true )
			return false, err
		end
		
		return true
	end,
	
	disconnect = function( self )
		self.svn:close()
	end,
	
	--- Attempts to login to the SVN server
	--
	-- @param username string containing the login username
	-- @param password string containing the login password
	-- @return status, true on success, false on failure
	-- @return brute.Error object on failure
	--         brute.Account object on success
	login = function( self, username, password )
		local status, msg		
		
		if ( self.invalid_users[username] ) then
			return false, brute.Error:new( "User is invalid" )
		end
	
		status, msg = self.svn:login( username, password )

		if ( not(status) and msg:match("Username not found") ) then
			self.invalid_users[username] = true
			return false, brute.Error:new("Username not found")
		elseif ( status and msg:match("success") ) then
			return true, brute.Account:new(username, password, creds.State.VALID)
		else
			return false, brute.Error:new( "Incorrect password" )
		end
	end,
	
	--- Verifies whether the repository is valid
	--
	-- @return status, true on success, false on failure
	-- @return err string containing an error message on failure
	check = function( self )
		local svn = svn:new( self.host, self.port, self.repo )
		local status = svn:connect()

		svn:close()

		if ( status ) then
			return true
		else
			return false, ("Failed to connect to SVN repository (%s)"):format(self.repo)
		end
	end,
}



action = function(host, port)
	local status, accounts 
	
	local repo = stdnse.get_script_args('svn-brute.repo')
	local force = stdnse.get_script_args('svn-brute.force')
	
	if ( not(repo) ) then
		return "No repository specified (see svn-brute.repo)"
	end
	
	local svn = svn:new( host, port, repo )
	local status = svn:connect()

	if ( status and svn.auth_mech["ANONYMOUS"] and not(force) ) then
		return "  \n  Anonymous SVN detected, no authentication needed"
	end
	
	if ( not(svn.auth_mech) or not( svn.auth_mech["CRAM-MD5"] ) ) then
		return "  \n  No supported authentication mechanisms detected"
	end
	
	local invalid_users = {}
	local engine = brute.Engine:new(Driver, host, port, invalid_users)
	engine.options.script_name = SCRIPT_NAME
	status, accounts = engine:start()
	if( not(status) ) then
		return accounts
	end

	return accounts
end
