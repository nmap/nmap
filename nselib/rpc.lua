---
-- RPC Library supporting a very limited subset of operations
--
-- Summary
-- -------
-- 	o The library works over both the UDP and TCP protocols
--	o A subset of nfs and mountd procedures are supported
--  o The versions 1 through 3 are supported for the nfs and mountd program
--  o Authentication is supported using the NULL RPC Authentication protocol
--
-- Overview
-- --------
-- The library contains the following classes:
--   o Comm 
--		- Handles low-level packet sending, recieving, decoding and encoding
--		- Used by Mount, NFS, RPC and Portmap
--   o Mount 
--		- Handles communication with the mount RPC program
--   o NFS 
--		- Handles communication with the nfs RPC program
--   o Helper 
--		- Provides easy access to common RPC functions
--		- Implemented as a static class where most functions accept host 
--        and port parameters
--   o RPC 
--		- Static container for constants
--   o Portmap
--		- Handles communication with the portmap RPC program
--   o Util
--	 	- Mostly static conversion routines
--
-- The portmapper dynamically allocates tcp/udp ports to RPC programs. So in
-- in order to request a list of NFS shares from the server we need to:
--  o Make sure that we can talk to the portmapper on port 111 tcp or udp
--  o Query the portmapper for the ports allocated to the NFS program
--  o Query the NFS program for a list of shares on the ports returned by the
--    portmap program.
--
-- The Helper class contains functions that facilitate access to common
-- RPC program procedures through static class methods. Most functions accept
-- host and port parameters. As the Helper functions query the portmapper to
-- get the correct RPC program port, the port supplied to these functions
-- should be the rpcbind port 111/tcp or 111/udp.
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
-- -- retrieve a list of NFS export
-- status, mounts = rpc.Helper.ShowMounts( host, port )
--
-- -- iterate over every share
-- for _, mount in ipairs( mounts ) do
--
-- 	-- get the NFS attributes for the share
--	status, attribs = rpc.Helper.GetAttributes( host, port, mount.name )
--		.... process NFS attributes here ....
--  end
-- </code>
--
-- Additional information
-- ----------------------
-- RPC transaction ID's (XID) are not properly implemented as a random ID is
-- generated for each client call. The library makes no attempt to verify
-- whether the returned XID is valid or not.
--
-- Therefore TCP is the preferred method of communication and the library
-- always attempts to connect to the TCP port of the RPC program first.
-- This behaviour can be overrided by setting the rpc.protocol argument.
-- The portmap service is always queried over the protocol specified in the
-- port information used to call the Helper function from the script.
--
-- When multiple versions exists for a specific RPC program the library
-- always attempts to connect using the highest available version.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
-- @args nfs.version number If set overrides the detected version of nfs
-- @args mount.version number If set overrides the detected version of mountd
-- @args rpc.protocol table If set overrides the preferred order in which
--       protocols are tested. (ie. "tcp", "udp")

module(... or "rpc", package.seeall)
require("datafiles")

-- Version 0.3
--
-- Created 01/24/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net> 
-- Revised 02/22/2010 - v0.2 - cleanup, revised the way TCP/UDP are handled fo
--                             encoding an decoding
-- Revised 03/13/2010 - v0.3 - re-worked library to be OO
--


-- Defines the order in which to try to connect to the RPC programs
-- TCP appears to be more stable than UDP in most cases, so try it first
local RPC_PROTOCOLS = ( nmap.registry.args and nmap.registry.args['rpc.protocol'] and type(nmap.registry.args['rpc.protocol']) == 'table') and nmap.registry.args['rpc.protocol'] or { "tcp", "udp" }

-- used to cache the contents of the rpc datafile
local RPC_PROGRAMS

-- Supported protocol versions
Version = {
	["nfs"] = { min=1, max=3 },
	["mountd"] = { min=1, max=3 },
}

math.randomseed( os.time() )

-- Low-level communication class
Comm = {

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	--- Checks if data contains enough bytes to read the <code>needed</code> amount
	--  If it doesn't it attempts to read the remaining amount of bytes from the socket
	--
	-- @param data string containing the current buffer
	-- @param pos number containing the current offset into the buffer
	-- @param needed number containing the number of bytes needed to be available
	-- @return status success or failure
	-- @return data string containing the data passed to the function and the additional data appended to it
	GetAdditionalBytes = function( self, data, pos, needed )

		local status = true
		local tmp

		if data:len() - pos + 1 < needed then
			local toread =  needed - ( data:len() - pos + 1 )
			status, tmp = self.socket:receive_bytes( toread )
			if status then
				data = data .. tmp
			else
				return false, string.format("getAdditionalBytes() failed to read: %d bytes from the socket", needed - ( data:len() - pos ) )
			end
		end
		return status, data
	end,

	--- Creates a RPC header
	--
	-- @param xid number
	-- @param program_id number containing the program_id to connect to
	-- @param program_version number containing the version to query
	-- @param procedure number containing the procedure to call
	-- @param auth table containing the authentication data to use
	-- @return string of bytes
	CreateHeader = function( self, xid, program_id, program_version, procedure, auth )
		local RPC_VERSION = 2
		local packet

		if not(xid) then
			xid = math.random(1234567890)
		end
		if not auth or auth.type ~= RPC.AuthType.Null then
			return false, "No or invalid authentication type specified"
		end

		packet = bin.pack( ">IIIIII", xid, RPC.MessageType.Call, RPC_VERSION, program_id, program_version, procedure )
		if auth.type == RPC.AuthType.Null then
			packet = packet .. bin.pack( "IIII", 0, 0, 0, 0 )
		end		
		return true, packet
	end,

	--- Decodes the RPC header (without the leading 4 bytes as received over TCP)
	--
	-- @param data string containing the buffer of bytes read so far
	-- @param pos number containing the current offset into data
	-- @return pos number containing the offset after the decoding
	-- @return header table containing <code>xid</code>, <code>type</code>, <code>state</code>,
	-- <code>verifier</code> and <code>accept_state</code>
	DecodeHeader = function( self, data, pos )
		local header = {}
		local status

		local HEADER_LEN = 20

		header.verifier = {}

		if ( data:len() - pos < HEADER_LEN ) then
			local tmp
			status, tmp = self:GetAdditionalBytes( data, pos, HEADER_LEN - ( data:len() - pos ) )
			if not status then
				return -1, nil
			end
			data = data .. tmp
		end

		pos, header.xid, header.type, header.state = bin.unpack(">III", data, pos)
		pos, header.verifier.flavor = bin.unpack(">I", data, pos)
		pos, header.verifier.length = bin.unpack(">I", data, pos) 

		if header.verifier.length - 8 > 0 then
			status, data = self:GetAdditionalBytes( data, pos, header.verifier.length - 8 )
			if not status then
				return -1, nil
			end
			pos, header.verifier.data = bin.unpack("A" .. header.verifier.length - 8, data, pos )
		end
		pos, header.accept_state = bin.unpack(">I", data, pos )
		return pos, header
	end,

	--- Reads the response from the socket
	--
	-- @return data string containing the raw response
	ReceivePacket = function( self )
		local status
		
		if ( self.proto == "udp" ) then
			-- There's not much we can do in here to check if we received all data
			-- as the packet contains no length field. It's up to each decoding function
			-- to do appropriate checks
			return self.socket:receive_bytes(1)
		else 
			local tmp, lastfragment, length
			local data, pos = "", 1

			repeat
				lastfragment = false
				status, data = self:GetAdditionalBytes( data, pos, 4 )
				if ( not(status) ) then
					return false, "rpc.Comm.ReceivePacket: failed to call GetAdditionalBytes"
				end
				
				pos, tmp = bin.unpack(">i", data, pos )
				length = bit.band( tmp, 0x7FFFFFFF )

				if ( bit.band( tmp, 0x80000000 ) == 0x80000000 ) then
					lastfragment = true
				end

				status, data = self:GetAdditionalBytes( data, pos, length )
				if ( not(status) ) then
					return false, "rpc.Comm.ReceivePacket: failed to call GetAdditionalBytes"
				end

				--
				-- When multiple packets are received they look like this
				-- H = Header data
				-- D = Data
				-- 
				-- We don't want the Header
				--
				-- HHHHDDDDDDDDDDDDDDHHHHDDDDDDDDDDD
				-- ^   ^             ^   ^
				-- 1   5             18  22
				--
				-- eg. we want
				-- data:sub(5, 18) and data:sub(22)
				-- 

				local bufcopy = data:sub(pos)

				if 1 ~= pos - 4 then
					bufcopy = data:sub(1, pos - 5) .. bufcopy
					pos = pos - 4
				else
					pos = 1
				end

				pos = pos + length
				data = bufcopy
			until lastfragment == true	
			return true, data
		end
	end,
	
	--- Encodes a RPC packet
	--
	-- @param xid number containing the transaction ID
	-- @param prog number containing the program id
	-- @param auth table containing authentication information
	-- @param data string containing the packet data
	-- @return packet string containing the encoded packet data
	EncodePacket = function( self, xid, prog, auth, data )
		local status, packet = self:CreateHeader( xid, prog.id, prog.version, prog.proc, auth )
		local len

		if ( not(status) ) then
			return
		end
		
		packet = packet .. ( data or "" )

		if ( self.proto == "udp") then
			return packet
		else
			-- set the high bit as this is our last fragment
			len = 0x80000000 + packet:len()
			return bin.pack(">I", len) .. packet 
		end
	end,
	
	SendPacket = function( self, packet )
		return self.socket:send( packet )
	end,
	
}

--- Mount class handling communication with the mountd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
Mount = {

	Procedure = 
	{
		MOUNT = 1,
		DUMP = 2,
		UMNT = 3,
		UMNTALL = 4,
		EXPORT = 5,
	},

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	--- Connects to the mountd program
	--
	-- @param host table
	-- @param port table
	-- @param version number containing the program version to use
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)
	Connect = function( self, host, port, version )
		local socket = nmap.new_socket()
		local status, result = socket:connect(host.ip, port.number, port.protocol)
		
		if ( status ) then
			self.socket = socket
			self.proto = port.protocol
			self.comm = Comm:new( { socket = socket, proto=port.protocol} )
			self.version = ( nmap.registry.args and nmap.registry.args['mount.version'] ) and tonumber(nmap.registry.args['mount.version']) or version
			
			if ( self.version > Version["mountd"].max or self.version < Version["mountd"].min ) then
				return false, "Library does not support mountd version: " .. self.version
			end
		end
		
		return status, result
	end,
	
	--- Disconnects from the mountd program
	--
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)
	Disconnect = function( self )
		local status, result = self.socket:close()
		if ( status ) then
			self.proto = nil
			self.socket = nil
			self.comm = nil
		end
		return status, result
	end,
		
	--- Requests a list of NFS export from the remote server
	--
	-- @return status success or failure
	-- @return entries table containing a list of share names (strings)
	Export = function( self )

		local catch = function() self.socket:close()	end
		local try = nmap.new_try(catch)
		local msg_type = 0
		local prg_mount = Util.ProgNameToNumber("mountd")
		local packet
		local pos = 1
		local header = {}
		local entries = {}
		local data = ""
		local status

		local REPLY_ACCEPTED, SUCCESS, PROC_EXPORT = 0, 0, 5

		if self.proto ~= "tcp" and self.proto ~= "udp" then
			return false, "Protocol should be either udp or tcp"
		end
		packet = self.comm:EncodePacket( nil, { id=prg_mount, version=self.version, proc=Mount.Procedure.EXPORT }, { type=RPC.AuthType.Null }, nil )
		try( self.comm:SendPacket( packet ) )

		status, data = self.comm:ReceivePacket()
		if ( not(status) ) then
			return false, "mountExportCall: Failed to read data from socket"
		end

		-- make sure we have atleast 24 bytes to unpack the header
		data = try( self.comm:GetAdditionalBytes( data, pos, 24 ) )
		pos, header = self.comm:DecodeHeader( data, pos )

		if not header then
			return false, "Failed to decode header"
		end

		if header.type ~= RPC.MessageType.Reply then
			return false, string.format("Packet was not a reply")
		end

		if header.state ~= REPLY_ACCEPTED then
			return false, string.format("Reply state was not Accepted(0) as expected")
		end

		if header.accept_state ~= SUCCESS then
			return false, string.format("Accept State was not Successful")
		end

		---
		--  Decode directory entries
		--
		--  [entry]
		--     4 bytes   - value follows (1 if more data, 0 if not)
		--     [Directory]
		--  	  4 bytes   - value len
		--  	  len bytes - directory name
		--  	  ? bytes   - fill bytes (@see calcFillByte)
		--     [Groups]
		--		   4 bytes  - value follows (1 if more data, 0 if not)
		--         [Group] (1 or more)
		--            4 bytes   - group len
		--			  len bytes - group value	
		-- 	          ? bytes   - fill bytes (@see calcFillByte)		  
		---
		while true do
			-- make sure we have atleast 4 more bytes to check for value follows
			data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )

			local data_follows
			pos, data_follows = bin.unpack( ">I", data, pos )

			if data_follows ~= 1 then
				break
			end

			--- Export list entry starts here
			local entry = {}
			local len	

			-- make sure we have atleast 4 more bytes to get the length
			data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
			pos, len = bin.unpack(">I", data, pos )

			data = try( self.comm:GetAdditionalBytes( data, pos, len ) )
			pos, entry.name = bin.unpack("A" .. len, data, pos )
			pos = pos + Util.CalcFillBytes( len )

			-- decode groups
			while true do
				local group 

				data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
				pos, data_follows = bin.unpack( ">I", data, pos )

				if data_follows ~= 1 then
					break
				end

				data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
				pos, len = bin.unpack( ">I", data, pos )
				data = try( self.comm:GetAdditionalBytes( data, pos, len ) )
				pos, group = bin.unpack( "A" .. len, data, pos )

				table.insert( entry, group )
				pos = pos + Util.CalcFillBytes( len )
			end		
			table.insert(entries, entry)
		end
		return true, entries
	end,


	--- Attempts to mount a remote export in order to get the filehandle
	--
	-- @param path string containing the path to mount
	-- @return status success or failure
	-- @return fhandle string containing the filehandle of the remote export
	Mount = function( self, path )

		local catch = function() self.socket:close()	end
		local try = nmap.new_try(catch)
		local packet, data
		local prog_id = Util.ProgNameToNumber("mountd")
		local _, pos, data, header, fhandle = "", 1, "", "", {}
		local status, len

		local REPLY_ACCEPTED, SUCCESS, MOUNT_OK = 0, 0, 0

		data = bin.pack(">IA", path:len(), path)

		for i=1, Util.CalcFillBytes( path:len() ) do
			data = data .. string.char( 0x00 )
		end

		packet = self.comm:EncodePacket( nil, { id=prog_id, version=self.version, proc=Mount.Procedure.MOUNT }, { type=RPC.AuthType.Null }, data )
		try( self.comm:SendPacket( packet ) )

		status, data = self.comm:ReceivePacket()
		if ( not(status) ) then
			return false, "mountCall: Failed to read data from socket"
		end

		pos, header = self.comm:DecodeHeader( data, pos )
		if not header then
			return false, "Failed to decode header"
		end

		if header.type ~= RPC.MessageType.Reply then
			return false, string.format("Packet was not a reply")
		end

		if header.state ~= REPLY_ACCEPTED then
			return false, string.format("Reply state was not Accepted(0) as expected")
		end

		if header.accept_state ~= SUCCESS then
			return false, string.format(3, "mountCall: Accept State was not Successful", path)
		end

		local mount_status
		data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
		pos, mount_status = bin.unpack(">I", data, pos )

		if mount_status ~= MOUNT_OK then
			if ( mount_status == 13 ) then
				return false, "Access Denied"
			else
				return false, string.format("Mount failed: %d", mount_status)
			end
		end

		if ( self.version == 3 ) then
			data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
			_, len = bin.unpack(">I", data, pos )
			data = try( self.comm:GetAdditionalBytes( data, pos, len + 4 ) )
			pos, fhandle = bin.unpack( "A" .. len + 4, data, pos )
		elseif ( self.version < 3 ) then
			data = try( self.comm:GetAdditionalBytes( data, pos, 32 ) )
			pos, fhandle = bin.unpack( "A32", data, pos )
		else
			return false, "Mount failed"
		end

		return true, fhandle
	end,

	--- Attempts to unmount a remote export in order to get the filehandle
	--
	-- @param path string containing the path to mount
	-- @return status success or failure
	-- @return error string containing error if status is false
	Unmount = function( self, path )

		local catch = function() self.socket:close()	end
		local try = nmap.new_try(catch)
		local packet, data
		local prog_id = Util.ProgNameToNumber("mountd")
		local _, pos, data, header, fhandle = "", 1, "", "", {}
		local status

		local REPLY_ACCEPTED, SUCCESS, MOUNT_OK = 0, 0, 0

		data = bin.pack(">IA", path:len(), path)

		for i=1, Util.CalcFillBytes( path:len() ) do
			data = data .. string.char( 0x00 )
		end

		packet = self.comm:EncodePacket( nil, { id=prog_id, version=self.version, proc=Mount.Procedure.UMNT }, { type=RPC.AuthType.Null }, data )
		try( self.comm:SendPacket( packet ) )

		status, data = self.comm:ReceivePacket( )
		if ( not(status) ) then
			return false, "mountCall: Failed to read data from socket"
		end

		pos, header = self.comm:DecodeHeader( data, pos )
		if not header then
			return false, "Failed to decode header"
		end

		if header.type ~= RPC.MessageType.Reply then
			return false, string.format("Packet was not a reply")
		end

		if header.state ~= REPLY_ACCEPTED then
			return false, string.format("Reply state was not Accepted(0) as expected")
		end

		if header.accept_state ~= SUCCESS then
			return false, string.format(3, "mountCall: Accept State was not Successful", path)
		end

		return true, ""
	end,

}

--- NFS class handling communication with the nfsd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
NFS = {

	-- Unfortunately the NFS procedure numbers differ in between versions
	Procedure = 
	{
		-- NFS Version 1
		[1] =
		{
			GETATTR = 1,
			ROOT = 3,
			LOOKUP = 4,
			EXPORT = 5,
			READDIR = 16,
			STATFS = 17,
		},

		-- NFS Version 2
		[2] = 
		{
			GETATTR = 1,
			ROOT = 3,
			LOOKUP = 4,
			EXPORT = 5,
			READDIR = 16,
			STATFS = 17,
		},

		-- NFS Version 3
		[3] = 
		{
			GETATTR = 1,
			SETATTR = 2,
			LOOKUP = 3,
			ACCESS = 4,
			EXPORT = 5,
			READDIR = 16,
			READDIRPLUS = 17,
			FSSTAT = 18,
			FSINFO = 19,
			PATHCONF = 20,
			COMMIT = 21,
		},
	},

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,

	--- Connects to the nfsd program
	--
	-- @param host table
	-- @param port table
	-- @param version number containing the program version to use
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)	
	Connect = function( self, host, port, version )
		local socket = nmap.new_socket()
		local status, result = socket:connect(host.ip, port.number, port.protocol)
		
		if ( status ) then
			self.socket = socket
			self.proto = port.protocol
			self.version = ( nmap.registry.args and nmap.registry.args['nfs.version'] ) and tonumber(nmap.registry.args['nfs.version']) or version

			if ( self.version > Version["nfs"].max or self.version < Version["nfs"].min ) then
				return false, "Library does not support nfsd version: " .. self.version
			end

			self.comm = Comm:new( { socket = socket, proto=port.protocol} )
		end
		
		return status, result
	end,
	
	--- Disconnects from the nfsd program
	--
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)
	Disconnect = function( self )
		local status, result = self.socket:close()
		if ( status ) then
			self.proto = nil
			self.socket = nil
			self.comm = nil
		end
		return status, result
	end,

	--- Decodes the READDIR section of a NFS ReadDir response
	--
	-- @param data string containing the buffer of bytes read so far
	-- @param pos number containing the current offset into data
	-- @return pos number containing the offset after the decoding
	-- @return entries table containing two table entries <code>attributes</code>
	--         and <code>entries</code>. The attributes entry is only present when
	--         using NFS version 3. The <code>entries</code> field contain one
	--         table for each file/directory entry. It has the following fields
	--         <code>file_id</code>, <code>name</code> and <code>cookie</code>
	--
	ReadDirDecode = function( self, data, pos )

		local entry, response = {}, {}
		local value_follows
		local status, _

		local NFS_OK = 0
	
		status, data = self.comm:GetAdditionalBytes( data, pos, 4 )
		if ( not(status) ) then
			return false, "ReadDirDecode failed"
		end
		
		pos, status = bin.unpack(">I", data, pos)
		if status ~= NFS_OK then
			return -1, nil
		end

		if ( 3 == self.version ) then
			local attrib = {}
			response.attributes = {}
			status, data = self.comm:GetAdditionalBytes( data, pos, 4 )
			if( not(status) ) then
				return false, "NFS.ReadDirDecode failed to get additional bytes from socket"
			end
			pos, value_follows = bin.unpack(">I", data, pos)
			if value_follows == 0 then
				return -1, nil
			end
			status, data = self.comm:GetAdditionalBytes( data, pos, 84 )
			if( not(status) ) then
				return false, "NFS.ReadDirDecode failed to get additional bytes from socket"
			end
			pos, attrib.type, attrib.mode, attrib.nlink, attrib.uid, attrib.gid, 
			attrib.size, attrib.used, attrib.rdev, attrib.fsid, attrib.fileid,
			attrib.atime, attrib.mtime, attrib.ctime = bin.unpack(">IIIIILLLLLLLL", data, pos)
			table.insert(response.attributes, attrib)
			-- opaque data
			status, data = self.comm:GetAdditionalBytes( data, pos, 8 )
			if ( not(status) ) then
				return false, "ReadDirDecode failed"
			end
			pos, _ = bin.unpack(">L", data, pos)
		end

		response.entries = {}
		while true do
			entry = {}
			status, data = self.comm:GetAdditionalBytes( data, pos, 4 )
			if ( not(status) ) then
				return false, "ReadDirDecode failed"
			end
	
			pos, value_follows = bin.unpack(">I", data, pos)

			if ( value_follows == 0 ) then
				break
			end

			if ( 3 == self.version ) then
				status, data = self.comm:GetAdditionalBytes( data, pos, 8 )
				if ( not(status) ) then
					return false, "ReadDirDecode failed"
				end
				pos, entry.fileid = bin.unpack(">L", data, pos )
			else
				status, data = self.comm:GetAdditionalBytes( data, pos, 4 ) 
				if ( not(status) ) then
					return false, "ReadDirDecode failed"
				end
				pos, entry.fileid = bin.unpack(">I", data, pos )
			end

			status, data = self.comm:GetAdditionalBytes( data, pos, 4 )
			if ( not(status) ) then
				return false, "ReadDirDecode failed"
			end
			
			pos, entry.length = bin.unpack(">I", data, pos)
			status, data = self.comm:GetAdditionalBytes( data, pos, entry.length )
			if ( not(status) ) then
				return false, "ReadDirDecode failed"
			end
			
			pos, entry.name = bin.unpack("A" .. entry.length, data, pos)
			pos = pos + Util.CalcFillBytes( entry.length )

			if ( 3 == self.version ) then
				status, data = self.comm:GetAdditionalBytes( data, pos, 8 )
				if ( not(status) ) then
					return false, "ReadDirDecode failed"
				end
				
				pos, entry.cookie = bin.unpack(">L", data, pos)
			else
				status, data = self.comm:GetAdditionalBytes(  data, pos, 4 )
				if ( not(status) ) then
					return false, "ReadDirDecode failed"
				end
				
				pos, entry.cookie = bin.unpack(">I", data, pos)
			end
			table.insert( response.entries, entry )
		end
		return pos, response	
	end,


	--- Reads the contents inside a NFS directory
	--
	-- @param file_handle string containing the filehandle to query
	-- @return status true on success, false on failure
	-- @return table of file table entries as described in <code>decodeReadDir</code>
	ReadDir = function( self, file_handle )

		local status, packet
		local cookie, count = 0, 8192
		local pos, data, _ = 1, "", ""
		local header, response = {}, {}

		if ( not(file_handle) ) then
			return false, "No filehandle received"
		end

		if ( self.version == 3 ) then
			local opaque_data = 0
			data = bin.pack("A>L>L>I", file_handle, cookie, opaque_data, count)	
		else
			data = bin.pack("A>I>I", file_handle, cookie, count)
		end		
		packet = self.comm:EncodePacket( nil, { id=Util.ProgNameToNumber("nfs"), version=self.version, proc=NFS.Procedure[self.version].READDIR }, { type=RPC.AuthType.Null }, data )
		status = self.comm:SendPacket( packet )
		if ( not(status) ) then
			return false, "nfsReadDir: Failed to write to socket"
		end		
	
		status, data = self.comm:ReceivePacket()
		if ( not(status) ) then
			return false, "nfsReadDir: Failed to read data from socket"
		end
		pos, header = self.comm:DecodeHeader( data, pos )

		if not header then
			return false, "Failed to decode header"
		end
		pos, response = self:ReadDirDecode( data, pos )
		return true, response
	end,

	--- Gets filesystem stats (Total Blocks, Free Blocks and Available block) on a remote NFS share
	--
	-- @param file_handle string containing the filehandle to query
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	-- @return errormsg if status is false
	StatFs = function( self, file_handle )

		local status, packet
		local pos, data, _ = 1, "", ""
		local header, statfs = {}, {}

		if ( self.version > 2 ) then
			return false, ("Version %d not supported"):format(self.version)
		end

		if ( not(file_handle) or file_handle:len() ~= 32 ) then
			return false, "Incorrect filehandle received"
		end

		data = bin.pack("A", file_handle )
		packet = self.comm:EncodePacket( nil, { id=Util.ProgNameToNumber("nfs"), version=self.version, proc=NFS.Procedure[self.version].STATFS }, { type=RPC.AuthType.Null }, data )
		status = self.comm:SendPacket( packet )
		if ( not(status) ) then
			return false, "nfsStatFs: Failed to write to socket"
		end		

		status, data = self.comm:ReceivePacket( )
		if ( not(status) ) then
			return false, "nfsStatFs: Failed to read data from socket"
		end

		pos, header = self.comm:DecodeHeader( data, pos )

		if not header then
			return false, "Failed to decode header"
		end

		pos, statfs = self:StatFsDecode( data, pos )

		if not statfs then
			return false, "Failed to decode statfs structure"
		end
		return true, statfs
	end,

	--- Attempts to decode the attributes section of the reply
	--
	-- @param data string containing the full statfs reply
	-- @param pos number pointing to the statfs section of the reply
	-- @return pos number containing the offset after decoding
	-- @return statfs table with the following fields: <code>type</code>, <code>mode</code>, 
	-- 	<code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
	--  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
	--  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
	--
	GetAttrDecode = function( self, data, pos )
		local attrib = {}
		local catch = function() self.socket:close()	end
		local try = nmap.new_try(catch)
		local NFS_OK = 0
		local status

		status, data = self.comm:GetAdditionalBytes( data, pos, 4 )
		if ( not(status) ) then
			return false, "GetAttrDecode: GetAdditionalBytes failed"
		end
	
		pos, attrib.status = bin.unpack(">I", data, pos)

		if attrib.status ~= NFS_OK then
			return -1, nil
		end
		if ( self.version < 3 ) then
			status, data = self.comm:GetAdditionalBytes( data, pos, 64 )
			if ( not(status) ) then
				return false, "GetAttrDecode: GetAdditionalBytes failed"
			end
			
			pos, attrib.type, attrib.mode, attrib.nlink, attrib.uid, 
			attrib.gid, attrib.size, attrib.blocksize, attrib.rdev,
			attrib.blocks, attrib.fsid, attrib.fileid, attrib.atime,
			attrib.mtime, attrib.ctime = bin.unpack( ">IIIIIIIIIILLL", data, pos )
			elseif ( self.version == 3 ) then
				status, data = self.comm:GetAdditionalBytes( data, pos, 84 )
				if ( not(status) ) then
					return false, "GetAttrDecode: GetAdditionalBytes failed"
				end
				pos, attrib.type, attrib.mode, attrib.nlink, attrib.uid,
				attrib.gid, attrib.size, attrib.used, attrib.rdev, 
				attrib.fsid, attrib.fileid, attrib.atime, attrib.mtime, 
				attrib.ctime = bin.unpack(">IIIIILLLLLLLL", data, pos)
			else
				return -1, "Unsupported version"
			end
			return pos, attrib
		end,

		--- Gets mount attributes (uid, gid, mode, etc ..) from a remote NFS share
		--
		-- @param file_handle string containing the filehandle to query
		-- @return status true on success, false on failure
		-- @return attribs table with the fields <code>type</code>, <code>mode</code>, 
		-- 	<code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
		--  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
		--  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
		-- @return errormsg if status is false
		GetAttr = function( self, file_handle )
			local data, packet, status, attribs, pos, header

			data = bin.pack("A", file_handle)
			packet = self.comm:EncodePacket( nil, { id=Util.ProgNameToNumber("nfs"), version=self.version, proc=NFS.Procedure[self.version].GETATTR }, { type=RPC.AuthType.Null }, data )
			status = self.comm:SendPacket(packet)
			if ( not(status) ) then
				return false, "nfsGetAttribs: Failed to send data to socket"
			end

			status, data = self.comm:ReceivePacket()
			if ( not(status) ) then
				return false, "nfsGetAttribs: Failed to read data from socket"
			end

			pos, header = self.comm:DecodeHeader( data, 1 )

			if not header then
				return false, "Failed to decode header"
			end

			pos, attribs = self:GetAttrDecode( data, pos )

			if not attribs then
				return false, "Failed to decode attrib structure"
			end

			return true, attribs
		end,

		--- Attempts to decode the StatFS section of the reply
		--
		-- @param data string containing the full statfs reply
		-- @param pos number pointing to the statfs section of the reply
		-- @return pos number containing the offset after decoding
		-- @return statfs table with the following fields: <code>transfer_size</code>, <code>block_size</code>, 
		-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
		--
		StatFsDecode = function( self, data, pos )
			local catch = function() self.socket:close()	end
			local try = nmap.new_try(catch)
			local statfs = {}
			local NFS_OK, NSFERR_ACCESS = 0, 13

			data = try( self.comm:GetAdditionalBytes( data, pos, 4 ) )
			pos, statfs.status = bin.unpack(">I", data, pos)

			if statfs.status ~= NFS_OK then
				if statfs.status == NSFERR_ACCESS then
					stdnse.print_debug("STATFS query received NSFERR_ACCESS")
				end
				return -1, nil
			end

			data = try( self.comm:GetAdditionalBytes( data, pos, 20 ) )
			pos, statfs.transfer_size, statfs.block_size, 
			statfs.total_blocks, statfs.free_blocks, 
			statfs.available_blocks = bin.unpack(">IIIII", data, pos )
			return pos, statfs
		end,
}

Helper = {

	--- Lists the NFS exports on the remote host
	-- This function abstracts the RPC communication with the portmapper from the user
	--
	-- @param host table
	-- @param port table
	-- @return status true on success, false on failure
	-- @return result table of string entries or error message on failure
	ShowMounts = function( host, port )
	
   		local data, prog_tbl = {}, {}
		local status, result, mounts, response 
		local socket = nmap.new_socket()
		local mountd
		local ver
		local mnt = Mount:new()			
		local portmap = Portmap:new()
		local portmap_table, proginfo

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")

		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for mountd"
		end
		
		status, result = mnt:Connect( host, mountd.port, mountd.version )
		if ( not(status) ) then
			stdnse.print_debug(3, result)
			return false, result
		end

		status, mounts = mnt:Export()
	
		mnt:Disconnect()
	
		return status, mounts
	end,

	--- Retrieves NFS storage statistics
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	ExportStats = function( host, port, path )

		local fhandle
		local stats, status, result
		local mountd, nfsd = {}, {}
		local mnt, nfs = Mount:new(), NFS:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd", 2)
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for mountd"
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs", 2)
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for nfsd"
		end

		status, result = mnt:Connect( host, mountd.port, mountd.version )
		if ( not(status) ) then
			return false, "Failed to connect to mountd program"
		end

		status, result = nfs:Connect( host, nfsd.port, nfsd.version )
		if ( not(status) ) then
			mnt:Disconnect()
			return false, "Failed to connect to nfsd program"
		end

		status, fhandle = mnt:Mount( path )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			stdnse.print_debug("rpc.Helper.ExportStats: mount failed")
			return false, "Mount failed"
		end

		status, stats = nfs:StatFs( fhandle )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			return false, stats
		end
		
		status, fhandle = mnt:Unmount( path )

		mnt:Disconnect()
		nfs:Disconnect()

		return true, stats
	end,

	--- Retrieves a list of files from the NFS export
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return table of file table entries as described in <code>decodeReadDir</code>
	Dir = function( host, port, path )

		local fhandle
		local dirs, status, result
		local mountd, nfsd = {}, {}
		local mnt, nfs = Mount:new(), NFS:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for mountd"
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for nfsd"
		end

		status, result = mnt:Connect( host, mountd.port, mountd.version )
		if ( not(status) ) then
			return false, "Failed to connect to mountd program"
		end

		status, result = nfs:Connect( host, nfsd.port, nfsd.version )
		if ( not(status) ) then
			mnt:Disconnect()
			return false, "Failed to connect to nfsd program"
		end

		status, fhandle = mnt:Mount( path )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			return false, "rpc.Helper.Dir: mount failed"
		end

		status, dirs = nfs:ReadDir( fhandle )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			return false, "rpc.Helper.Dir: statfs failed"
		end
		
		status, fhandle = mnt:Unmount( path )
	
		mnt:Disconnect()
		nfs:Disconnect()
	
		if ( not(status) ) then
			return false, "rpc.Helper.Dir: mount failed"
		end

		return true, dirs

	end,

	--- Retrieves NFS Attributes
	--
	-- @param host table
	-- @param port table
	-- @param path string containing the nfs export path
	-- @return status true on success, false on failure
	-- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
	-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
	GetAttributes = function( host, port, path )
		local fhandle
		local attribs, status, result
		local mountd, nfsd = {}, {}
		local mnt, nfs = Mount:new(), NFS:new()

		status, mountd = Helper.GetProgramInfo( host, port, "mountd")
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for mountd"
		end

		status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
		if ( not(status) ) then
			return false, "Failed to retrieve rpc information for nfsd"
		end

		status, result = mnt:Connect( host, mountd.port, mountd.version )
		if ( not(status) ) then
			return false, "Failed to connect to mountd program"
		end

		status, result = nfs:Connect( host, nfsd.port, nfsd.version )
		if ( not(status) ) then
			mnt:Disconnect()
			return false, "Failed to connect to nfsd program"
		end

		status, fhandle = mnt:Mount( path )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			return false, "rpc.Helper.GetAttributes: mount failed"
		end

		status, attribs = nfs:GetAttr( fhandle )
		if ( not(status) ) then
			mnt:Disconnect()
			nfs:Disconnect()
			return false, "rpc.Helper.GetAttributes: GetAttr failed"
		end
		
		status, fhandle = mnt:Unmount( path )
	
		mnt:Disconnect()
		nfs:Disconnect()
	
		if ( not(status) ) then
			return false, "rpc.Helper.ExportStats: mount failed"
		end

		return true, attribs
	end,
	
	--- Queries the portmapper for a list of programs
	--
	-- @param host table
	-- @param port table
	-- @return status true on success, false on failure
	-- @return table containing the portmapper information as returned by 
	-- <code>Portmap.Dump</code>
	RpcInfo = function( host, port )
		local portmap = Portmap:new()
		local status = Portmap:Connect(host, port)
		local result

		if ( not(status) ) then
			return
		end

		status, result = portmap:Dump()
		portmap:Disconnect()

		return status, result
	end,
		
	--- Queries the portmapper for a port for the specified RPC program
	--
	-- @param host table
	-- @param port table
	-- @param program_id number containing the RPC program ID
	-- @param protocol string containing either "tcp" or "udp"
	-- @return status true on success, false on failure
	-- @return table containing the portmapper information as returned by 
	-- <code>Portmap.Dump</code>
	GetPortForProgram = function( host, port, program_id, protocol )
		local portmap = Portmap:new()
		local status = Portmap:Connect(host, port)
		local result

		if ( not(status) ) then
			return
		end

		status, result = portmap:GetPort( program_id, protocol, 1 )
		portmap:Disconnect()

		return status, result
	end,
	
	--- Get RPC program information
	--
	-- @param host table
	-- @param port table
	-- @param program string containing the RPC program name
	-- @param max_version (optional) number containing highest version to retrieve
	-- @return status true on success, false on failure
	-- @return info table containing <code>port</code>, <code>port.number</code>
	-- <code>port.protocol</code> and <code>version</code>
	GetProgramInfo = function( host, port, program, max_version )
	
		local status, response
		local portmap_table, info
		local portmap = Portmap:new()

		status, response = portmap:Connect( host, port )
		if ( not(status) ) then
			return false, "rpc.Helper.ShowMounts: Failed to connect to portmap"
		end
		status, portmap_table = portmap:Dump()
		if ( not(status) ) then
			portmap:Disconnect()
			return false, "rpc.Helper.ShowMounts: Failed to GetProgramVersions"
		end
		status = portmap:Disconnect()
		if ( not(status) ) then
			return false, "rpc.Helper.ShowMounts: Failed to disconnect from portmap"
		end

		-- assume failure
		status = false

		for _, p in ipairs( RPC_PROTOCOLS ) do
			local tmp = portmap_table[Util.ProgNameToNumber(program)]

			if ( tmp and tmp[p] ) then
				info = {}
				info.port = {}
				info.port.number = tmp[p].port
				info.port.protocol = p
				-- choose the highest version available
				if ( not(Version[program]) ) then
					info.version = tmp[p].version[#tmp[p].version]
					status = true
				else
					for i=#tmp[p].version, 1, -1 do
						if ( Version[program].max >= tmp[p].version[i] ) then
							if ( not(max_version) ) then
								info.version = tmp[p].version[i]
								status = true
								break
							else
								if ( max_version >= tmp[p].version[i] ) then
									info.version = tmp[p].version[i]
									status = true
									break			
								end
							end
						end
					end
				end
				break
			end
		end

		return status, info
	end,

}

--- Container class for RPC constants
RPC = 
{
	AuthType =
	{
		Null = 0
	},	

	MessageType =
	{
		Call = 0,
		Reply = 1
	},

	Procedure =
	{
		[2] = 
		{
			GETPORT = 3,
			DUMP = 4,
		},
	
	},
	
}

--- Portmap class
Portmap = 
{
	PROTOCOLS = { 
		['tcp'] = 6, 
		['udp'] = 17, 
	},
	
	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	--- Connects to the Portmapper
	--
	-- @param host table
	-- @param port table
	-- @param version number containing the program version to use
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)
	Connect = function( self, host, port, version )
		local socket = nmap.new_socket()
		local status, result = socket:connect(host.ip, port.number, port.protocol)
		
		if ( status ) then
			self.socket = socket
			self.version = version or 2
			self.protocol = port.protocol
		end
		
		return status, result
	end,

	--- Disconnects from the portmapper program
	--
	-- @return status boolean true on success, false on failure
	-- @return result string containing error message (if status is false)
	Disconnect = function( self )
		local status, result = self.socket:close()
		if ( status ) then
			self.socket = nil
		end
		return status, result
	end,
	
	--- Dumps a list of RCP programs from the portmapper
	--
	-- @return status boolean true on success, false on failure
	-- @return result table containing RPC program information or error message
	--         on failure. The table has the following format:
	--
	-- <code>
	-- table[program_id][protocol]["port"] = <port number>
	-- table[program_id][protocol]["version"] = <table of versions>
	-- </code>
	--
	-- Where
	--  o program_id is the number associated with the program
	--  o protocol is either "tcp" or "udp"
	--
	Dump = function( self )
		local status, data, packet, response, pos, header
		
		local prog_id = Util.ProgNameToNumber("rpcbind")
		local prog_proc = RPC.Procedure[self.version].DUMP
		local comm 
		
		if ( self.program_table ) then
			return true, self.program_table
		end

		comm = Comm:new( { socket=self.socket, proto=self.protocol } )
		packet = comm:EncodePacket( nil, { id=prog_id, version=self.version, proc=prog_proc }, { type=RPC.AuthType.Null }, data )
		status, response = comm:SendPacket( packet )
		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "Portmap.Dump: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, 1 )
		if ( not(header) ) then
			return false, "Failed to decode RPC header"
		end
		if header.accept_state ~= 0 then
			return false, string.format("RPC Accept State was not Successful")
		end

		self.program_table = {}

		while true do
			local vfollows
			local program, version, protocol, port

			status, data = comm:GetAdditionalBytes( data, pos, 4 ) 
			pos, vfollows = bin.unpack( ">I", data, pos )
					
			if ( vfollows == 0 ) then
				break
			end
			
			pos, program, version, protocol, port = bin.unpack(">IIII", data, pos)

			if ( protocol == Portmap.PROTOCOLS.tcp ) then
				protocol = "tcp"
			elseif ( protocol == Portmap.PROTOCOLS.udp ) then
				protocol = "udp"
			end
						
			self.program_table[program] = self.program_table[program] or {}
			self.program_table[program][protocol] = self.program_table[program][protocol] or {}
			self.program_table[program][protocol]["port"] = port
			self.program_table[program][protocol]["version"] = self.program_table[program][protocol]["version"] or {}
			table.insert( self.program_table[program][protocol]["version"], version )
			-- parts of the code rely on versions being in order
			-- this way the highest version can be chosen by choosing the last element
			table.sort( self.program_table[program][protocol]["version"] )
		end

		return true, self.program_table
	
	end,
	
	--- Queries the portmapper for the port of the selected program, 
	--  protocol and version
	--
	-- @param program string name of the program
	-- @param protocol string containing either "tcp" or "udp"
	-- @param version number containing the version of the queried program
	-- @return number containing the port number
	GetPort = function( self, program, protocol, version )
		local status, data, response, header, pos, packet
		local xid
		local prog_id = Util.ProgNameToNumber("rpcbind") -- RPC Portmap
		local prog_proc = RPC.Procedure[self.version].GETPORT
		local comm
		
		if ( not( Portmap.PROTOCOLS[protocol] ) ) then
			return false, ("Protocol %s not supported"):format(protocol)
		end
		
		if ( Util.ProgNameToNumber( program ) == nil ) then
			return false, ("Unknown program name: %s"):format(program)
		end
						
		comm = Comm:new( { socket=self.socket, proto=self.protocol } )
		data = bin.pack( ">I>I>I>I", Util.ProgNameToNumber(program), version, Portmap.PROTOCOLS[protocol], 0 )
		packet = comm:EncodePacket( xid, { id=prog_id, version=self.version, proc=prog_proc }, { type=RPC.AuthType.Null }, data )
		
		status = comm:SendPacket(packet)
		data = ""
		
		status, data = comm:ReceivePacket()
		if ( not(status) ) then
			return false, "GetPort: Failed to read data from socket"
		end

		pos, header = comm:DecodeHeader( data, 1 )
		
		if ( not(header) ) then
			return false, "Failed to decode RPC header"
		end
		
		if header.accept_state ~= 0 then
			return false, string.format("RPC Accept State was not Successful")
		end
		status, data = comm:GetAdditionalBytes( data, pos, 4 ) 
		return true, select(2, bin.unpack(">I", data, pos ) )
		
	end,
		
}

--- Static class containing mostly conversion functions
Util =
{
	--- Converts a RPC program name to it's equivalent number
	--
	-- @param prog_name string containing the name of the RPC program
	-- @return num number containing the program ID
	ProgNameToNumber = function(prog_name)
		local status
		
		if not( RPC_PROGRAMS ) then
			status, RPC_PROGRAMS = datafiles.parse_rpc()
			if ( not(status) ) then
				return
			end
		end
		for num, name in pairs(RPC_PROGRAMS) do
			if ( prog_name == name ) then
				return num
			end
		end
		
		return
	end,
	
	--- Converts the RPC program number to it's equivalent name
	--
	-- @param num number containing the RPC program identifier
	-- @return string containing the RPC program name
	ProgNumberToName = function( num )
		local status
		
		if not( RPC_PROGRAMS ) then
			status, RPC_PROGRAMS = datafiles.parse_rpc()
			if ( not(status) ) then
				return
			end
		end
		return RPC_PROGRAMS[num]
	end,
	
	--- Converts a numeric ACL mode as returned from <code>mnt.GetAttr</code>
	--  to octal
	--
	-- @param num number containing the ACL mode
	-- @return num containing the octal ACL mode
	ToAclMode = function( num )
		return ( ("%o"):format(bit.bxor(num, 0x4000)) )
	end,
	
	--- Converts a numeric ACL to it's character equivalent eg. (rwxr-xr-x)
	--
	-- @param num number containing the ACL mode
	ToAclText = function( num )
		local mode = num
		local txtmode = ""

		for i=0,2 do
			if ( bit.band( mode, bit.lshift(0x01, i*3) ) == bit.lshift(0x01, i*3) ) then
				-- Check for SUID or SGID
				if ( i>0 and bit.band( mode, 0x400 * i ) == 0x400 * i ) then
					txtmode = "s" .. txtmode
				else
					txtmode = "x" .. txtmode
				end
			else
				if ( i>0 and bit.band( mode, 0x400 * i ) == 0x400 * i ) then
					txtmode = "S" .. txtmode
				else
					txtmode = "-" .. txtmode
				end
			end
			if ( bit.band( mode, bit.lshift(0x02, i*3) ) == bit.lshift(0x02, i*3) ) then
				txtmode = "w" .. txtmode
			else
				txtmode = "-" .. txtmode
			end
			if ( bit.band( mode, bit.lshift(0x04, i*3) ) == bit.lshift(0x04, i*3) ) then
				txtmode = "r" .. txtmode
			else
				txtmode = "-" .. txtmode
			end
		end
		
		if ( bit.band(mode, 0x4000) == 0x4000 ) then
			txtmode = "d" .. txtmode
		else
			txtmode = "-" .. txtmode
		end
	
		return txtmode
	end,
	
	--
	-- Calculates the number of fill bytes needed
	-- @param length contains the length of the string
	-- @return the amount of pad needed to be divideable by 4
	CalcFillBytes = function(length)
	    -- calculate fill bytes
	    if math.mod( length, 4 ) ~= 0 then
	    	return (4 - math.mod( length, 4))
	    else
	    	return 0
	    end
	end
	
}
