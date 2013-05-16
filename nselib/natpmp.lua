---
-- This library implements the basics of NAT-PMP as described in the
-- NAT Port Mapping Protocol (NAT-PMP) draft:
--   o http://tools.ietf.org/html/draft-cheshire-nat-pmp-03
-- 
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
local bin = require "bin"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
_ENV = stdnse.module("natpmp", stdnse.seeall)

local ResultCode = {	
	SUCCESS 			= 0,
	UNSUPPORTED_VERSION = 1,
	NOT_AUTHORIZED 		= 2,
	NETWORK_FAILURE 	= 3,
	OUT_OF_RESOURCES	= 4,
	UNSUPPORTED_OPCODE	= 5,
}

local ErrorMessage = {
	[ResultCode.UNSUPPORTED_VERSION] 	= "The device did not support the protocol version",
	[ResultCode.NOT_AUTHORIZED] 		= "The operation was not authorized",
	[ResultCode.NETWORK_FAILURE]		= "Network failure",
	[ResultCode.OUT_OF_RESOURCES]		= "The device is out of resources",
	[ResultCode.UNSUPPORTED_OPCODE]		= "The requested operation was not supported",
}


Request = {
	
	GetWANIP = {
		
		new = function(self)
			local o = { version = 0, op = 0 }
			setmetatable(o, self)
			self.__index = self
			return o
	  	end,
		
		__tostring = function(self)
			return bin.pack(">CC", self.version, self.op)
		end,
		
	},
	
	MapPort = {
		
		new = function(self, pubport, privport, proto, lifetime)
			assert(proto == "udp" or proto == "tcp", "Unsupported protocol")
			local o = { 
				version = 0,
				pubport = pubport,
				privport = privport,
				proto = proto,
				lifetime = lifetime or 3600
			}
			setmetatable(o, self)
			self.__index = self
			return o
	  	end,

		__tostring = function(self)
			return bin.pack(">CCSSSI", 
				self.version, 
				(self.proto=="udp" and 1 or 2),
				0, -- reserved
				self.privport, self.pubport,
				self.lifetime)
		end,
		
	}
	
}

Response = {
	
	GetWANIP = {
	
		new = function(self, data)
			local o = { data = data }
			setmetatable(o, self)
			self.__index = self
			if ( o:parse() ) then
				return o
			end
	  	end,

		parse = function(self)
			if ( #self.data ~= 12 ) then
				return
			end
		
			local pos
			pos, self.version, self.op, self.rescode = bin.unpack("<CCS", self.data)
		
			if ( self.rescode ~= ResultCode.SUCCESS or self.op ~= 128 ) then
				return
			end
		
			pos, self.time, self.ip = bin.unpack("<II", self.data, pos)
			self.ip = ipOps.fromdword(self.ip)
			self.time = stdnse.format_timestamp(self.time)
			return true
		end,
		
	},
	
	MapPort = {
		
		new = function(self, data)
			local o = { data = data }
			setmetatable(o, self)
			self.__index = self
			if ( o:parse() ) then
				return o
			end
	  	end,

		parse = function(self)
			if ( #self.data ~= 16 ) then
				return
			end
			
			local pos
			pos, self.version, self.op, self.rescode = bin.unpack("<CCS", self.data)
		
			if ( self.rescode ~= ResultCode.SUCCESS ) then
				return
			end
			
			pos, self.time, self.privport, self.pubport, self.lifetime = bin.unpack(">ISSI", self.data, pos)
			return true
		end,
	}
	
	
}





Helper = {
		
	new = function(self, host, port)
		local o = { host = host, port = port }
		setmetatable(o, self)
		self.__index = self
		return o
  	end,
	
	exchPacket = function(self, data)
		local socket = nmap.new_socket("udp")
		socket:set_timeout(5000)
		
		local status = socket:sendto(self.host, self.port, data)
		if ( not(status) ) then
			socket:close()
			return false, "Failed to send request to device"
		end
		
		local response
		status, response = socket:receive()	
		socket:close()
		if ( not(status) ) then
			return false, "Failed to receive response from router"
		end
		return true, response
	end,
	
	--- Gets the WAN ip of the router
	getWANIP = function(self)
		local packet = Request.GetWANIP:new()
		local status, response = self:exchPacket(tostring(packet))
		if ( not(status) ) then
			return status, response
		end
		
		response = Response.GetWANIP:new(response)
		if ( not(response) ) then
			return false, "Failed to parse response from router"
		end

		return true, response
	end,
	
	--- Maps a public port to a private port
	-- @param pubport number containing the public external port to map
	-- @param privport number containing the private internal port to map
	-- @param protocol string containing the protocol to map (udp|tcp)
	-- @param lifetime [optional] number containing the lifetime in seconds
	mapPort = function(self, pubport, privport, protocol, lifetime)
		local packet = Request.MapPort:new(pubport, privport, protocol, lifetime)
		local status, response = self:exchPacket(tostring(packet))
		if ( not(status) ) then
			return status, response
		end
		
		response = Response.MapPort:new(response)
		if ( not(response) ) then
			return false, "Failed to parse response from router"
		end

		return true, response
	end,
	
	unmapPort = function(self, pubport, privport)
		return self:mapPort(pubport, privport, 0)
	end,
	
	unmapAllPorts = function(self)
		return self.mapPort(0, 0, 0)
	end,
	
}

return _ENV;
