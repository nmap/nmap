---
-- A library that implements the basics of the STUN protocol (Session
-- Traversal Utilities for NAT) per RFC3489 and RFC5389. A protocol
-- overview is available at http://en.wikipedia.org/wiki/STUN.
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

local bin = require "bin"
local ipOps = require "ipOps"
local match = require "match"
local math = require "math"
local nmap = require "nmap"
local package = require "package"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("stun", stdnse.seeall)

-- The supported request types
MessageType = {
	BINDING_REQUEST		= 0x0001,
	BINDING_RESPONSE	= 0x0101,
}
	
-- The header used in both request and responses
Header = {
		
	-- the header size in bytes		
	size = 20,
	
	-- creates a new instance of Header
	-- @param type number the request/response type
	-- @param trans_id string the 128-bit transaction id
	-- @param length number the packet length
	new = function(self, type, trans_id, length)
		local o = { type = type, trans_id = trans_id, length = length or 0 }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- parses an opaque string and creates a new Header instance
	-- @param data opaque string 
	-- @return header new instance of Header
	parse = function(data)
		local header = Header:new()
		local pos
		pos, header.type, header.length, header.trans_id = bin.unpack(">SSA16", data)
		return header
	end,
	
	-- converts the header to an opaque string
	-- @return string containing the header instance
	__tostring = function(self)
		return bin.pack(">SSA", self.type, self.length, self.trans_id)
	end,		
}

Request = {
	
	-- The binding request
	Bind = {
		
		-- Creates a new Bind request
		-- @param trans_id string containing the 128 bit transaction ID
		-- @return o new instance of the Bind request
		new = function(self, trans_id)
			local o = { 
				header = Header:new(MessageType.BINDING_REQUEST, trans_id),
				attributes = {}
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- converts the instance to an opaque string
		-- @return string containing the Bind request as string
		__tostring = function(self)
			local data = ""
			for _, attrib in ipairs(self.attributes) do
				data = data .. tostring(attrib)
			end
			self.header.length = #data
			return tostring(self.header) .. data			
		end,	
	}
	
}

-- The attribute class
Attribute = {

	MAPPED_ADDRESS 		= 0x0001,
	RESPONSE_ADDRESS	= 0x0002,
	CHANGE_REQUEST		= 0x0003,
	SOURCE_ADDRESS		= 0x0004,
	CHANGED_ADDRESS		= 0x0005,
	USERNAME			= 0x0006,
	PASSWORD			= 0x0007,
	MESSAGE_INTEGRITY	= 0x0008,
	ERROR_CODE			= 0x0009,
	UNKNOWN_ATTRIBUTES	= 0x000a,
	REFLECTED_FROM		= 0x000b,
	SERVER				= 0x8022,
	
	-- creates a new attribute instance
	-- @param type number containing the attribute type
	-- @param data string containing the attribute value
	-- @return o instance of attribute
	new = function(self, type, data)
		local o = {
			type = type,
			length = (data and #data or 0),
			data = data,
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- parses a string and creates an Attribute instance
	-- @param data string containing the raw attribute
	-- @return o new attribute instance
	parse = function(data)
		local attr = Attribute:new()
		local pos = 1
		
		pos, attr.type, attr.length = bin.unpack(">SS", data, pos)
					
		local function parseAddress(data, pos)
			local _, addr = nil, {}
			pos, _, addr.family, addr.port, addr.ip = bin.unpack("<CCSI", data, pos)
			if ( addr.ip ) then
				addr.ip = ipOps.fromdword(addr.ip)
			end
			return addr
		end
		
		if ( ( attr.type == Attribute.MAPPED_ADDRESS ) or
			 ( attr.type == Attribute.RESPONSE_ADDRESS ) or
			 ( attr.type == Attribute.SOURCE_ADDRESS ) or
			 ( attr.type == Attribute.CHANGED_ADDRESS ) ) then
			if ( attr.length ~= 8 )	then
				stdnse.print_debug(2, "Incorrect attribute length")
			end
			attr.addr = parseAddress(data, pos)
		elseif( attr.type == Attribute.SERVER ) then
			pos, attr.server = bin.unpack("A" .. attr.length-1, data, pos)
		end
		
		return attr
	end,
	
	-- converts an attribute to string
	-- @return string containing the serialized attribute
	__tostring = function(self)
		return bin.pack(">SSA", self.type, self.length, self.data or "")
	end,
	
}

-- Response class container
Response = {
	
	-- Bind response class
	Bind = {
		
		-- creates a new instance of the Bind response
		-- @param trans_id string containing the 128 bit transaction id
		-- @return o new Bind instance
		new = function(self, trans_id)
			local o = { header = Header:new(MessageType.BINDING_RESPONSE, trans_id) }
			setmetatable(o, self)
			self.__index = self
			return o
		end,

		-- parses a raw string and creates a new Bind instance
		-- @param data string containing the raw data
		-- @return resp containing a new Bind instance
		parse = function(data)
			local resp = Response.Bind:new()
			local pos = Header.size
			
			resp.header = Header.parse(data)
			resp.attributes = {}

			while( pos < #data ) do
				local attr = Attribute.parse(data:sub(pos))
				table.insert(resp.attributes, attr)
				pos = pos + attr.length + 4
			end			
			return resp
		end
	}
}

-- The communication class
Comm = {
	
	-- creates a new Comm instance
	-- @param host table
	-- @param port table
	-- @param options table, currently supporting:
	--        <code>timeout</code> - socket timeout in ms.
	-- @param mode containing the mode 
	-- @return o new instance of Comm
	new = function(self, host, port, options, mode)
		local o = { 
			host = host,
			port = port,
			options = options or { timeout = 10000 },
			socket = nmap.new_socket(),
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- connects the socket to the server
	-- @return status true on success, false on failure
	-- @return err string containing an error message, if status is false
	connect = function(self)
		self.socket:set_timeout(self.options.timeout)
		return self.socket:connect(self.host, self.port)
	end,
	
	-- sends a request to the server
	-- @return status true on success, false on failure
	-- @return err string containing an error message, if status is false
	send = function(self, data)
		return self.socket:send(data)
	end,

	-- receives a response from the server
	-- @return status true on success, false on failure
	-- @return response containing a response instance
	--         err string containing an error message, if status is false
	recv = function(self)	
		local status, hdr_data = self.socket:receive_buf(match.numbytes(Header.size), false)
		if ( not(status) ) then
			return false, "Failed to receive response from server"
		end
		
		local header = Header.parse(hdr_data)
		if ( not(header) ) then
			return false, "Failed to parse response header"
		end
		
		local status, data = self.socket:receive_buf(match.numbytes(header.length), false)
		if ( header.type == MessageType.BINDING_RESPONSE ) then
			local resp = Response.Bind.parse(hdr_data .. data)
			return true, resp
		end
		
		return false, "Unknown response message received"
	end,
	
	-- sends the request instance to the server and receives the response
	-- @param req request class instance
	-- @return status true on success, false on failure
	-- @return response containing a response instance
	--         err string containing an error message, if status is false
	exch = function(self, req)
		local status, err = self:send(tostring(req))
		if ( not(status) ) then
			return false, "Failed to send request to server"
		end
		return self:recv()	
	end,
	
	-- closes the connection to the server
	-- @return status true on success, false on failure
	-- @return err string containing an error message, if status is false
	close = function(self)
		self.socket:close()
	end,
}

-- The Util class
Util = {
	
	-- creates a random string
	-- @param len number containg the length of the generated random string
	-- @return str containing the random string
	randomString = function(len)
		local str = ""
		for i=1, len do str = str .. string.char(math.random(255)) end
		return str
	end
	
}

-- The Helper class
Helper = {

	-- creates a new Helper instance
	-- @param host table
	-- @param port table
	-- @param options table, currently supporting:
	--        <code>timeout</code> - socket timeout in ms.
	-- @param mode containing the mode container, currently Classic is the only
	--        supported container
	-- @return o new instance of Comm
	new = function(self, host, port, options, mode)
		local o = { 
			mode = mode,
			comm = Comm:new(host, port, options, mode),
		}
		o.mode = stdnse.get_script_args("stun.mode") or "modern"
		assert(o.mode == "modern" or o.mode == "classic", "Unsupported mode")
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- connects to the server
	-- @return status true on success, false on failure
	-- @return err string containing an error message, if status is false
	connect = function(self)
		return self.comm:connect()
	end,
	
	-- Get's the external public IP
	-- @return status true on success, false on failure
	-- @return result containing the IP as tring
	getExternalAddress = function(self)
		local trans_id
		
		if ( self.mode == "classic" ) then
		 	trans_id = Util.randomString(16)
		else
			trans_id = bin.pack("HA","2112A442", Util.randomString(12))
		end
		local req = Request.Bind:new(trans_id)
		
		local status, response = self.comm:exch(req)
		if ( not(status) ) then
			return false, "Failed to send data to server"
		end
		
		local result
		for k, attr in pairs(response.attributes) do
			if (attr.type == Attribute.MAPPED_ADDRESS ) then
				result = ( attr.addr and attr.addr.ip or "<unknown>" )
			end
			if ( attr.type == Attribute.SERVER ) then
				self.cache = self.cache or {}
				self.cache.server = attr.server
			end
		end
		
		if ( not(result) and not(self.cache) ) then
			return false, "Server returned no response"
		end
		
		return status, result
	end,
	
	-- Gets the server version if it was returned by the server
	-- @return status true on success, false on failure
	-- @return version string containing the server product and version
	getVersion = function(self)
		local status, response = false, nil
		-- check if the server version was cached
		if ( not(self.cache) or not(self.cache.version) ) then
			local status, response = self:getExternalAddress()
			if ( status ) then
				return true, (self.cache and self.cache.server or "")
			end
			return false, response
		end
		return true, (self.cache and self.cache.server or "")
	end,
	
	-- closes the connection to the server
	-- @return status true on success, false on failure
	-- @return err string containing an error message, if status is false
	close = function(self)
		return self.comm:close()
	end,
	
}

return _ENV;
