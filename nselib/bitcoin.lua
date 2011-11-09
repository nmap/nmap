---
-- This library implements a minimal subset of the BitCoin protocol
-- It currently supports the version handshake and processing Addr responses.
--
-- The library contains the following classes:
--
-- * NetworkAddress - Contains functionality for encoding and decoding the
--                    BitCoin network address structure.
--
-- * Request - Classs containing BitCoin client requests
--     o Version - The client version exchange packet
--
-- * Response - Class containing BitCoin server responses
--     o Version - The server version exchange packet
--     o VerAck  - The server version ACK packet
--     o Addr    - The server address packet
--     o Inv     - The server inventory packet
--
-- * BCSocket - A buffering socket class
--
-- * Helper - The primary interface to scripts
--

--
-- Version 0.1
-- 
-- Created 11/09/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

module(... or "bitcoin", package.seeall)

require 'ipOps'
stdnse.silent_require('openssl')


-- A class that supports the BitCoin network address structure
NetworkAddress = {
	
	NODE_NETWORK = 1,
	
	-- Creates a new instance of the NetworkAddress class
	-- @param host table as received by the action method
	-- @param port table as received by the action method
	-- @return o instance of NetworkAddress
	new = function(self, host, port)
		local o = {
			host = "table" == type(host) and host.ip or host,
			port = "table" == type(port) and port.number or port,
			service = NetworkAddress.NODE_NETWORK,
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- Creates a new instance of NetworkAddress based on the data string
	-- @param data string of bytes
	-- @return na instance of NetworkAddress
	fromString = function(data)
		assert(26 == #data, "Expected 26 bytes of data")
		
		local na = NetworkAddress:new()
		local _
		_, na.service, na.ipv6_prefix, na.host, na.port = bin.unpack("<LH12I>S", data)
		na.host = ipOps.fromdword(na.host)
		return na
	end,
	
	-- Converts the NetworkAddress instance to string
	-- @return data string containing the NetworkAddress instance
	__tostring = function(self)
		local ipv6_prefix = "00 00 00 00 00 00 00 00 00 00 FF FF"
		local ip = ipOps.todword(self.host)
		return bin.pack("<LH>IS", self.service, ipv6_prefix, ip, self.port )
	end
}

-- The request class container
Request = {
	
	-- The version request
	Version = {
		
		-- Creates a new instance of the Version request
		-- @param host table as received by the action method
		-- @param port table as received by the action method
		-- @param lhost string containing the source IP
		-- @param lport number containing the source port
		-- @return o instance of Version
		new = function(self, host, port, lhost, lport)
			local o = { 
				host = host,
				port = port,
				lhost= lhost,
				lport= lport,
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the Version request to a string
		-- @return data as string
		__tostring = function(self)
			local magic = 0xD9B4BEF9
			local cmd = "version\0\0\0\0\0"
			local len = 85
			-- ver: 0.4.0
			local ver = 0x9c40
			
			-- NODE_NETWORK = 1
			local services = 1
			local timestamp = os.time()
			local ra = NetworkAddress:new(self.host, self.port)
			local sa = NetworkAddress:new(self.lhost, self.lport)
			local nodeid = openssl.rand_bytes(8)
			local subver = "\0"
			local lastblock = 0
			
			return bin.pack("<IAIILLAAAAI", magic, cmd, len, ver, services,
				timestamp, tostring(ra), tostring(sa), nodeid, subver, lastblock)
		end,
	},
	
	-- The GetAddr request
	GetAddr = {
		
		-- Creates a new instance of the Version request
		-- @param host table as received by the action method
		-- @param port table as received by the action method
		-- @param lhost string containing the source IP
		-- @param lport number containing the source port
		-- @return o instance of Version
		new = function(self, host, port, lhost, lport)
			local o = { 
				host = host,
				port = port,
				lhost= lhost,
				lport= lport,
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the Version request to a string
		-- @return data as string
		__tostring = function(self)
			local magic = 0xD9B4BEF9
			local cmd = "getaddr\0\0\0\0\0"
			local len = 0
			local chksum = 0x5DF6E0E2

			return bin.pack("<IAII", magic, cmd, len, chksum)
		end
	}
	
}

-- The response class container
Response = {
	
	-- The version response message
	Version = {
		
		-- Creates a new instance of Version based on data string
		-- @param data string containing the raw response
		-- @return o instance of Version
		new = function(self, data)
			local o = { data = data }
			setmetatable(o, self)
			self.__index = self
			o:parse()
			return o
		end,
		
		-- Parses the raw data and builds the Version instance
		parse = function(self)
			local pos, ra, sa
			pos, self.magic, self.cmd, self.len, self.ver_raw, self.service,
				self.timestamp, ra, sa, self.nodeid,
				self.subver, self.lastblock = bin.unpack("<IA12IILLA26A26H8CI", self.data)
			
			local function decode_bitcoin_version(n)
	        	if ( n < 31300 ) then
	                local minor, micro = n / 100, n % 100
	                return ("0.%d.%d"):format(minor, micro)
		        else
	                local minor, micro = n / 10000, (n / 100) % 100
				    return ("0.%d.%d"):format(minor, micro)
				end
			end
			
			self.ver = decode_bitcoin_version(self.ver_raw)
			self.sa = NetworkAddress.fromString(sa)
			self.ra = NetworkAddress.fromString(ra)
		end,		
	},
	
	-- The verack response message
	VerAck = {
		
		-- Creates a new instance of VerAck based on data string
		-- @param data string containing the raw response
		-- @return o instance of Version
		new = function(self, data)
			local o = { data = data }
			setmetatable(o, self)
			self.__index = self
			o:parse()
			return o
		end,
		
		-- Parses the raw data and builds the VerAck instance
		parse = function(self)
			local pos
			pos, self.magic, self.cmd = bin.unpack("<IA12", self.data)
		end,		
	},

	-- The Addr response message
	Addr = {
		
		-- Creates a new instance of VerAck based on data string
		-- @param data string containing the raw response
		-- @return o instance of Addr
		new = function(self, data, version)
			local o = { data = data, version=version }
			setmetatable(o, self)
			self.__index = self
			o:parse()
			return o
		end,
		
		-- Parses the raw data and builds the Addr instance
		parse = function(self)
			local pos, count
			pos, self.magic, self.cmd, self.len, self.chksum, count = bin.unpack("<IA12IIC", self.data)
			self.addresses = {}
			for c=1, count do
				if ( self.version > 31402 ) then
					local timestamp, data
					pos, timestamp, data = bin.unpack("<IA26", self.data, pos)
					local na = NetworkAddress.fromString(data)
					table.insert(self.addresses, { ts = timestamp, address = na })
				end
			end
			
		end,		
	},
	
	-- The inventory server packet
	Inv = {
	
		-- Creates a new instance of VerAck based on data string
		-- @param data string containing the raw response
		-- @return o instance of Addr
		new = function(self, data, version)
			local o = { data = data, version=version }
			setmetatable(o, self)
			self.__index = self
			o:parse()
			return o
		end,
		
		-- Parses the raw data and builds the Addr instance
		parse = function(self)
			local pos, count
			pos, self.magic, self.cmd, self.len = bin.unpack("<IA12II", self.data)
		end,		
	},
	
	-- Receives the packet and decodes it
	-- @param socket BCSocket instance
	-- @param version number containing the server version
	-- @return status true on success, false on failure
	-- @return response instance of response packet if status is true
	--         err string containing the error message if status is false
	recvPacket = function(socket, version)
		local status, header = socket:recv(20)
		if ( not(status) ) then
			return false, "Failed to read the packet header"
		end
		
		local pos, magic, cmd, len = bin.unpack("<IA12I", header)
		local data = ""
		
		if ( cmd ~= "version\0\0\0\0\0" and cmd ~= "verack\0\0\0\0\0\0") then
			len = len + 4
		end
		
		-- the verack has no payload
		if ( 0 ~= len ) then
			status, data = socket:recv(len)
			if ( not(status) ) then
				return false, "Failed to read the packet header"
			end
		end
		return Response.decode(header .. data, version)
	end,
	
	-- Decodes the raw packet data
	-- @param data string containing the raw packet
	-- @param version number containing the server version
	-- @return status true on success, false on failure
	-- @return response instance of response packet if status is true
	--         err string containing the error message if status is false
	decode = function(data, version)
		local pos, magic, cmd = bin.unpack("<IA12", data)
		if ( "version\0\0\0\0\0" == cmd ) then
			return true, Response.Version:new(data)
		elseif ( "verack\0\0\0\0\0\0" == cmd ) then
			return true, Response.VerAck:new(data)
		elseif ( "addr\0\0\0\0\0\0\0\0" == cmd ) then
			return true, Response.Addr:new(data, version)
		elseif ( "inv\0\0\0\0\0\0\0\0\0" == cmd ) then
			return true, Response.Inv:new(data)
		else
			return false, ("Unknown command (%s)"):format(cmd)
		end
	end,	
}
	
-- A buffered socket implementation
BCSocket =
{	
	retries = 3,
	
	-- Creates a new BCSocket instance 
	-- @param host table as received by the action method
	-- @param port table as received by the action method
	-- @param options table containing additional options
	--    <code>timeout</code> - the socket timeout in ms
	-- @return instance of BCSocket
	new = function(self, host, port, options)
		local o = { 
			host = host,
			port = port,
			timeout = "table" == type(options) and options.timeout or 10000
		}
       	setmetatable(o, self)
        self.__index = self
		o.Socket = nmap.new_socket()
		o.Buffer = nil
		return o
	end,
	
	--- Establishes a connection.
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	connect = function( self )
		self.Socket:set_timeout( self.timeout )
		return self.Socket:connect( self.host, self.port )
	end,
	
	--- Closes an open connection.
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	close = function( self )
		return self.Socket:close()
	end,
	
	--- Opposed to the <code>socket:receive_bytes</code> function, that returns
	-- at least x bytes, this function returns the amount of bytes requested.
	--
	-- @param count of bytes to read
	-- @return true on success, false on failure
	-- @return data containing bytes read from the socket
	-- 		   err containing error message if status is false
	recv = function( self, count )
		local status, data
	
		self.Buffer = self.Buffer or ""
	
		if ( #self.Buffer < count ) then
			status, data = self.Socket:receive_bytes( count - #self.Buffer )
			if ( not(status) or #data < count - #self.Buffer ) then
				return false, data
			end
			self.Buffer = self.Buffer .. data
		end
			
		data = self.Buffer:sub( 1, count )
		self.Buffer = self.Buffer:sub( count + 1)
	
		return true, data	
	end,
	
	--- Sends data over the socket
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	send = function( self, data )
		return self.Socket:send( data )
	end,
}

-- The Helper class used as a primary interface to scripts
Helper = {
	
	-- Creates a new Helper instance 
	-- @param host table as received by the action method
	-- @param port table as received by the action method
	-- @param options table containing additional options
	--    <code>timeout</code> - the socket timeout in ms
	-- @return instance of Helper
	new = function(self, host, port, options)
		local o = { 
			host = host,
			port = port,
			options = options
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	-- Connects to the BitCoin Server
	-- @return status true on success false on failure
	-- @return err string containing the error message in case status is false
	connect = function(self)
		self.socket = BCSocket:new(self.host, self.port, self.options)
		local status, err = self.socket:connect()
		
		if ( not(status) ) then
			return false, err
		end
		status, self.lhost, self.lport = self.socket.Socket:get_info()
		return status, (status and nil or self.lhost)
	end,

	-- Performs a version handshake with the server
	-- @return status, true on success false on failure
	-- @return version instance if status is true
	--         err string containing an error message if status is false
	exchVersion = function(self)
		if ( not(self.socket) ) then
			return false
		end

		local req = Request.Version:new(
			self.host, self.port, self.lhost, self.lport
		)

		local status, err = self.socket:send(tostring(req))
		if ( not(status) ) then
			return false, "Failed to send \"Version\" request to server"
		end
		
		local version
		status, version = Response.recvPacket(self.socket)
		
		if ( not(status) or not(version) or version.cmd ~= "version\0\0\0\0\0" ) then
			return false, "Failed to read \"Version\" response from server"
		end
		
		if ( version.ver_raw > 29000 ) then
			local status, verack = Response.recvPacket(self.socket)
		end
		
		self.version = version.ver_raw
		return status, version
	end,
	
	getNodes = function(self)
		local req = Request.GetAddr:new(
			self.host, self.port, self.lhost, self.lport
		)

		local status, err = self.socket:send(tostring(req))
		if ( not(status) ) then
			return false, "Failed to send \"Version\" request to server"
		end
		
		return Response.recvPacket(self.socket, self.version)
	end,
	
	-- Reads a message from the server
	-- @return status true on success, false on failure
	-- @return response instance of response packet if status is true
	--         err string containing the error message if status is false
	readMessage = function(self)
		assert(self.version, "Version handshake has not been performed")
		return Response.recvPacket(self.socket, self.version)	
	end,

	-- Closes the connection to the server
	-- @return status true on success false on failure
	-- @return err code, if status is false
	close = function(self)
		return self.socket:close()
	end	
}
