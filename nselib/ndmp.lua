---
-- A minimalistic NDMP (Network Data Management Protocol) library
--
-- @author Patrik Karlsson <patrik@cqure.net>
--

local bin = require "bin"
local bit = require "bit"
local match = require "match"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("ndmp", stdnse.seeall)

NDMP = {
	
	-- Message types
	MessageType = {
		CONFIG_GET_HOST_INFO 	= 0x00000100,
		CONFIG_GET_FS_INFO		= 0x00000105,
		CONFIG_GET_AUTH_ATTR	= 0x00000103,
		CONFIG_GET_SERVER_INFO 	= 0x00000108,
		CONNECT_CLIENT_AUTH		= 0x00000901,
	},
	
	-- The fragment header, 4 bytes where the highest bit is used to determine
	-- whether the fragment is the last or not.	
	FragmentHeader = {
		size = 4,
		
		-- Creates a new instance of fragment header
		-- @return o instance of Class
		new = function(self)
			local o = {	
				last = true,
				length = 24,
			}
			setmetatable(o, self)
			self.__index = self
			return o		
		end,
		
		-- Parse data stream and create a new instance of this class
		-- @param data opaque string
		-- @return fh new instance of FragmentHeader class
		parse = function(data)
			local fh = NDMP.FragmentHeader:new()
			local _, tmp = bin.unpack(">I", data)
			fh.length = bit.band(tmp, 0x7fffffff)
			fh.last= bit.rshift(tmp, 31)
			return fh
		end,
		
		-- Serializes the instance to an opaque string
		-- @return str string containing the serialized class
		__tostring = function(self)
			local tmp = 0
			if ( self.last ) then
				tmp = 0x80000000
			end
			tmp = tmp + self.length
			return bin.pack(">I", tmp)
		end,
		
	},
	
	-- The ndmp 24 byte header
	Header = {
		size = 24,

		-- creates a new instance of Header
		-- @return o instance of Header
		new = function(self)
			local o = {	
				seq = 0,
				time = os.time(),
				type = 0,
				msg = 0x00000108,
				reply_seq = 0,
				error = 0,
			}
			setmetatable(o, self)
			self.__index = self
			return o		
		end,
		
		-- Create a Header instance from opaque data string
		-- @param data opaque string
		-- @return hdr new instance of Header
		parse = function(data)
			local hdr = NDMP.Header:new()
			local pos
			pos, hdr.seq, hdr.time, hdr.type, hdr.msg, hdr.reply_seq, hdr.error = bin.unpack(">IIIIII", data)
			return hdr
		end,
		
		-- Serializes the instance to an opaque string
		-- @return str string containing the serialized class instance
		__tostring = function(self)
			return bin.pack(">IIIIII", self.seq, self.time, self.type, self.msg, self.reply_seq, self.error)
		end,
		
	},
}
			
NDMP.Message = {}

NDMP.Message.ConfigGetServerInfo = {

	-- Creates a Config Server Info instance
	-- @return o new instance of Class
	new = function(self)
		local o = {
			frag_header = NDMP.FragmentHeader:new(),
			header = NDMP.Header:new(),
			data = nil,
		}
		o.header.msg = NDMP.MessageType.CONFIG_GET_SERVER_INFO
		setmetatable(o, self)
		self.__index = self
		return o		
	end,
	
	-- Create a ConfigGetServerInfo instance from opaque data string
	-- @param data opaque string
	-- @return msg new instance of ConfigGetServerInfo
	parse = function(data)
		local msg = NDMP.Message.ConfigGetServerInfo:new()
		msg.frag_header = NDMP.FragmentHeader.parse(data)
		data = data:sub(NDMP.FragmentHeader.size + 1)
		msg.header = NDMP.Header.parse(data)
		msg.data = data:sub(NDMP.Header.size + 1)
		
		msg.serverinfo = {}
		local pos, err = bin.unpack(">I", msg.data)
		pos, msg.serverinfo.vendor = Util.parseString(msg.data, pos)
		pos, msg.serverinfo.product = Util.parseString(msg.data, pos)
		pos, msg.serverinfo.version = Util.parseString(msg.data, pos)
		return msg
	end,

	-- Serializes the instance to an opaque string
	-- @return str string containing the serialized class instance
	__tostring = function(self)
		return tostring(self.frag_header) .. tostring(self.header) .. tostring(self.data or "")
	end,					

}

NDMP.Message.ConfigGetHostInfo = {
	new = function(self)
		local o = {
			frag_header = NDMP.FragmentHeader:new(),
			header = NDMP.Header:new(),
			data = nil,
		}
		o.header.msg = NDMP.MessageType.CONFIG_GET_HOST_INFO
		setmetatable(o, self)
		self.__index = self
		return o		
	end,

	parse = function(data)
		local msg = NDMP.Message.ConfigGetServerInfo:new()
		msg.frag_header = NDMP.FragmentHeader.parse(data)
		data = data:sub(NDMP.FragmentHeader.size + 1)
		msg.header = NDMP.Header.parse(data)
		msg.data = data:sub(NDMP.Header.size + 1)
		
		msg.hostinfo = {}
		local pos, err = bin.unpack(">I", msg.data)
		pos, msg.hostinfo.hostname = Util.parseString(msg.data, pos)
		pos, msg.hostinfo.ostype = Util.parseString(msg.data, pos)
		pos, msg.hostinfo.osver = Util.parseString(msg.data, pos)
		pos, msg.hostinfo.hostid = Util.parseString(msg.data, pos)		
		return msg
	end,
	
	__tostring = function(self)
		return tostring(self.frag_header) .. tostring(self.header) .. tostring(self.data or "")
	end,					
}

NDMP.Message.ConfigGetFsInfo = {

	new = function(self)
		local o = {
			frag_header = NDMP.FragmentHeader:new(),
			header = NDMP.Header:new(),
			data = nil,
			fsinfo = {},
		}
		o.header.msg = NDMP.MessageType.CONFIG_GET_FS_INFO
		setmetatable(o, self)
		self.__index = self
		return o		
	end,
	
	parse = function(data)
		local msg = NDMP.Message.ConfigGetFsInfo:new()
		msg.frag_header = NDMP.FragmentHeader.parse(data)
		data = data:sub(NDMP.FragmentHeader.size + 1)
		msg.header = NDMP.Header.parse(data)
		msg.data = data:sub(NDMP.Header.size + 1)
		
		local pos, err, count = bin.unpack(">II", msg.data)
		for i=1, count do
			local item = {}
			pos, item.invalid = bin.unpack(">I", msg.data, pos)
			pos, item.fs_type = Util.parseString(msg.data, pos)
			pos, item.fs_logical_device = Util.parseString(msg.data, pos)
			pos, item.fs_physical_device = Util.parseString(msg.data, pos)
			pos, item.total_size = bin.unpack(">L", msg.data, pos)
			pos, item.used_size = bin.unpack(">L", msg.data, pos)
			pos, item.avail_size = bin.unpack(">L", msg.data, pos)
			pos, item.total_inodes = bin.unpack(">L", msg.data, pos)
			pos, item.used_inodes = bin.unpack(">L", msg.data, pos)
			pos, item.fs_env = Util.parseString(msg.data, pos)
			pos, item.fs_status = Util.parseString(msg.data, pos)	
			table.insert(msg.fsinfo, item)
		end
		return msg
	end,
	
	__tostring = function(self)
		return tostring(self.frag_header) .. tostring(self.header) .. tostring(self.data or "")
	end,					
}

NDMP.Message.UnhandledMessage = {
	
	new = function(self)
		local o = {
			frag_header = NDMP.FragmentHeader:new(),
			header = NDMP.Header:new(),
			data = nil,
		}
		setmetatable(o, self)
		self.__index = self
		return o		
	end,
	
	parse = function(data)
		local msg = NDMP.Message.ConfigGetFsInfo:new()
		msg.frag_header = NDMP.FragmentHeader.parse(data)
		data = data:sub(NDMP.FragmentHeader.size + 1)
		msg.header = NDMP.Header.parse(data)
		msg.data = data:sub(NDMP.Header.size + 1)
		return msg
	end,
	
	__tostring = function(self)
		return tostring(self.frag_header) .. tostring(self.header) .. tostring(self.data or "")
	end
	
}

Util = {
	
	parseString = function(data, pos)
		local pos, str = bin.unpack(">a", data, pos)
		local pad = ( 4 - ( #str % 4 ) ~= 4 ) and 4 - ( #str % 4 ) or 0
		return pos + pad, str
	
	end,
	
}

NDMP.TypeToMessage = {
	[NDMP.MessageType.CONFIG_GET_SERVER_INFO] = NDMP.Message.ConfigGetServerInfo,
	[NDMP.MessageType.CONFIG_GET_HOST_INFO] = NDMP.Message.ConfigGetHostInfo,
	[NDMP.MessageType.CONFIG_GET_FS_INFO] = NDMP.Message.ConfigGetFsInfo,
}

-- Handles the communication with the NDMP service
Comm = {
	
	-- Creates new Comm instance
	-- @param host table as received by the action method
	-- @param port table as receuved by the action method
	-- @return o new instance of Comm
	new = function(self, host, port)
		local o = {
			host = host,
			port = port,
			socket = nmap.new_socket(),
			seq = 0,
			in_queue = {},
		}
		setmetatable(o, self)
		self.__index = self
		return o		
	end,
	
	-- Connects to the NDMP server
	-- @return status true on success, false on failure
	connect = function(self)
		-- some servers seem to take their time, so leave this as 10s for now
		self.socket:set_timeout(10000)
		return self.socket:connect(self.host, self.port)
	end,
	
	-- Receives a message from the server
	-- @return status true on success, false on failure
	-- @return msg NDMP message when a parser exists, otherwise nil
	sock_recv = function(self)	
		local status, frag_data = self.socket:receive_buf(match.numbytes(4), true)
		if ( not(status) ) then
			return false, "Failed to read NDMP 4-byte fragment header"
		end
		local frag_header = NDMP.FragmentHeader.parse(frag_data)

		local status, header_data = self.socket:receive_buf(match.numbytes(24), true)
		if ( not(status) ) then
			return false, "Failed to read NDMP 24-byte header"
		end
		local header = NDMP.Header.parse(header_data)

		local status, data = self.socket:receive_buf(match.numbytes(frag_header.length - 24), true)
		if ( not(status) ) then
			return false, "Failed to read NDMP data"
		end
		
		if ( NDMP.TypeToMessage[header.msg] ) then
			return true, NDMP.TypeToMessage[header.msg].parse(frag_data .. header_data .. data)
		end
		return true, NDMP.Message.UnhandledMessage.parse(frag_data .. header_data .. data)
	end,
	
	recv = function(self)
		if ( #self.in_queue > 0 ) then
			return true, table.remove(self.in_queue, 1)
		end
		return self:sock_recv()
	end,
	
	-- Sends a message to the server
	-- @param msg NDMP message
	-- @return status true on success, false on failure
	-- @return err string containing the error message when status is false
	send = function(self, msg)
		self.seq = self.seq + 1
		msg.header.seq = self.seq
		return self.socket:send(tostring(msg))
	end,
	
	
	exch = function(self, msg)
		local status, err = self:send(msg)
		if ( not(status) ) then
			return false, "Failed to send ndmp Message to server"
		end
		local s_seq = msg.header.seq

		for k, v in ipairs(self.in_queue) do
			if ( v.reply_seq == s_seq ) then
				return true, table.remove(self.in_queue, k)
			end
		end

		while(true) do
			local reply
			status, reply = self:sock_recv()
			if ( not(status) ) then
				return false, "Failed to receive msg from server" 
			elseif ( reply and reply.header and reply.header.reply_seq == s_seq ) then
				return true, reply
			else
				table.insert(self.in_queue, reply)
			end
		end		
	end,
	
	close = function(self) return self.socket:close() end,
	
}


Helper = {
	
	new = function(self, host, port)
		local o = { comm = Comm:new(host, port) }
		setmetatable(o, self)
		self.__index = self
		return o		
	end,
		
	connect = function(self)
		return self.comm:connect()
	end,
	
	getFsInfo = function(self)
		return self.comm:exch(NDMP.Message.ConfigGetFsInfo:new())
	end,
	
	getHostInfo = function(self)
		return self.comm:exch(NDMP.Message.ConfigGetHostInfo:new())
	end,
	
	getServerInfo = function(self)
		return self.comm:exch(NDMP.Message.ConfigGetServerInfo:new())
	end,
	
	close = function(self)
		return self.comm:close()
	
	end
	
}

return _ENV;
