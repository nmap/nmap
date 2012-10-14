---
-- The VNC library provides some basic functionality needed in order to
-- communicate with VNC servers, and derivates such as Tight- or Ultra-
-- VNC.
--
-- Summary
-- -------
-- The library currently supports the VNC Authentication security type only.
-- This security type is supported by default in VNC, TightVNC and 
-- "Remote Desktop Sharing" in eg. Ubuntu. For servers that do not support
-- this authentication security type the login method will fail. 
--
-- Overview
-- --------
-- The library contains the following classes:
-- 
--   o VNC
--		- This class contains the core functions needed to communicate with VNC
--

-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"

-- Version 0.1
-- Created 07/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

local bin = require "bin"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("vnc", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require,'openssl')

VNC = {

	-- We currently support version 3.8 of the protocol only
	versions = {
		["RFB 003.003\n"] = "3.3",
		["RFB 003.007\n"] = "3.7",
		["RFB 003.008\n"] = "3.8",

		-- Mac Screen Sharing, could probably be used to fingerprint OS
		["RFB 003.889\n"] = "3.889",
	},
	
	sectypes = {
		INVALID = 0,
		NONE = 1,
		VNCAUTH = 2,
		RA2 = 5,
		RA2NE = 6,
		TIGHT = 16,
		ULTRA = 17,
		TNS = 18,
		VENCRYPT = 19,
		GTK_VNC_SASL = 20,
		MD5 = 21,
		COLIN_DEAN_XVP = 22,
		MAC_OSX_SECTYPE_30 = 30,
		MAC_OSX_SECTYPE_35 = 35,
	},
	
	-- Security types are fetched from the rfbproto.pdf
	sectypes_str = {
		[0] = "Invalid security type",
		[1] = "None",
		[2] = "VNC Authentication",
		[5] = "RA2",
		[6] = "RA2ne",
		[16]= "Tight",
		[17]= "Ultra",
		[18]= "TLS",
		[19]= "VeNCrypt",
		[20]= "GTK-VNC SASL",
		[21]= "MD5 hash authentication",
		[22]= "Colin Dean xvp",
		
		-- Mac OS X screen sharing uses 30 and 35
		[30]= "Mac OS X security type (30)",
		[35]= "Mac OS X security type (35)",
	},
	
	new = function(self, host, port)
		local o = {
			host = host,
			port = port,
			socket = nmap.new_socket(),
			cli_version = nmap.registry.args['vnc-brute.version'] or "RFB 003.889\n"
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Connects the VNC socket
	connect = function(self)
		if ( not(HAVE_SSL) ) then
			return false, "The VNC module requires OpenSSL support"
		end
		return self.socket:connect(self.host, self.port, "tcp")
	end,
	
	--- Disconnects the VNC socket
	disconnect = function(self)
		return self.socket:close()
	end,
	
	--- Performs the VNC handshake and determines
	-- o The RFB Protocol to use
	-- o The supported authentication security types
	--
	-- @return status, true on success, false on failure
	-- @return error string containing error message if status is false
	handshake = function(self)
		local status, data = self.socket:receive_buf(match.numbytes(12), true)
		local vncsec = {
			count = 1,
			types = {}
		}
		
		if ( not(status) ) then
			return status, "ERROR: VNC:handshake failed to receive protocol version"
		end
		
		self.protover = VNC.versions[data]
		if ( not(self.protover) ) then
			stdnse.print_debug("ERROR: VNC:handshake unsupported version (%s)", data:sub(1,11))
			return false, ("Unsupported version (%s)"):format(data:sub(1,11))
		end
			
		status = self.socket:send( self.cli_version )
		if ( not(status) ) then
			stdnse.print_debug("ERROR: VNC:handshake failed to send client version")
			return false, "ERROR: VNC:handshake failed"
		end

		local function process_error()
			local status, tmp = self.socket:receive_buf(match.numbytes(4), true)
			if( not(status) ) then
				return false, "VNC:handshake failed to retrieve error message"
			end
			local len = select(2, bin.unpack(">I", tmp))
			local status, err = self.socket:receive_buf(match.numbytes(len), true)
			if( not(status) ) then
				return false, "VNC:handshake failed to retrieve error message"
			end
			return false, err
		end

		if ( self.protover == "3.3" ) then
			local status, tmp = self.socket:receive_buf(match.numbytes(4), true)
			if( not(status) ) then
				return false, "VNC:handshake failed to receive security data"
			end

			vncsec.types[1] = select(2, bin.unpack("I", tmp) )
			self.vncsec = vncsec
			
			-- do we have an invalid security type, if so we need to handle an
			-- error condition
			if ( vncsec.types[1] == 0 ) then
				return process_error()
			end
		else
			local status, tmp = self.socket:receive_buf(match.numbytes(1), true)
			if ( not(status) ) then
				stdnse.print_debug("ERROR: VNC:handshake failed to receive security data")
				return false, "ERROR: VNC:handshake failed to receive security data"
			end

			vncsec.count = select(2, bin.unpack("C", tmp))
			if ( vncsec.count == 0 ) then
				return process_error()
			end
			status, tmp = self.socket:receive_buf(match.numbytes(vncsec.count), true)

			if ( not(status) ) then
				stdnse.print_debug("ERROR: VNC:handshake failed to receive security data")
				return false, "ERROR: VNC:handshake failed to receive security data"
			end

			for i=1, vncsec.count do
				table.insert( vncsec.types, select(2, bin.unpack("C", tmp, i) ) )
			end
			self.vncsec = vncsec
		end
		
		return true
	end,
	
	--- Creates the password bit-flip needed before DES encryption
	--
	-- @param password string containing the password to process
	-- @return password string containing the processed password
	createVNCDESKey = function( self, password )
		if ( #password < 8 ) then
			for i=1, (8 - #password) do
				password = password .. string.char(0x00)
			end
		end
		
		local newpass = ""
		for i=1, 8 do
			local _, bitstr = bin.unpack("B", password, i)
			newpass = newpass .. bin.pack("B", bitstr:reverse())
		end
		return newpass
	end,
	
	--- Attempts to login to the VNC service
	-- Currently the only supported auth sectype is VNC Authentication
	--
	-- @param username string, could be anything when VNCAuth is used
	-- @param password string containing the password to use for authentication
	-- @return status true on success, false on failure
	-- @return err string containing error message when status is false
	login = function( self, username, password )
		if ( not(password) ) then
			return false, "No password was supplied"
		end
	
		if ( not( self:supportsSecType( VNC.sectypes.VNCAUTH ) ) ) then
			return false, "The server does not support the \"VNC Authentication\" security type."
		end
	
		-- Announce that we support VNC Authentication
		local status = self.socket:send( bin.pack("C", VNC.sectypes.VNCAUTH) )
		if ( not(status) ) then
			return false, "Failed to select authentication type"
		end
	
		local status, chall = self.socket:receive_buf(match.numbytes(16), true)
		if ( not(status) ) then
			return false, "Failed to receive authentication challenge"
		end

		local key = self:createVNCDESKey(password)
		local resp = openssl.encrypt("des-ecb", key, nil, chall, false )

		status = self.socket:send( resp )
		if ( not(status) ) then
			return false, "Failed to send authentication response to server"
		end
		
		local status, result = self.socket:receive_buf(match.numbytes(4), true)
		if ( not(status) ) then
			return false, "Failed to retrieve authentication status from server"
		end
		
		if ( select(2, bin.unpack("I", result) ) ~= 0 ) then
			return false, ("Authentication failed with password %s"):format(password)
		end
		return true, ""
	end,
	
	--- Returns all supported security types as a table of strings
	--
	-- @return table containing a string entry for each security type
	getSecTypesAsStringTable = function( self )
		local tmp = {}
		for i=1, self.vncsec.count do
			table.insert( tmp, VNC.sectypes_str[self.vncsec.types[i]] or ("Unknown security type (%d)"):format(self.vncsec.types[i]) )
		end
		return true, tmp
	end,
	
	--- Checks if the supplied security type is supported or not
	--
	-- @param sectype number containing the security type to check for
	-- @return status true if supported, false if not supported
	supportsSecType = function( self, sectype )
		for i=1, self.vncsec.count do
			if ( self.vncsec.types[i] == sectype ) then
				return true
			end
		end
		return false
	end,
	
	--- Returns the protocol version reported by the server
	--
	-- @param version string containing the version number
	getProtocolVersion = function( self )
		return self.protover
	end,
	
}

return _ENV;
