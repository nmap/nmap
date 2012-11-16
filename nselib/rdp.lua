---
-- A minimal RDP (Remote Desktop Protocol) library. Currently has functionality to determine encryption
-- and cipher support.
-- 
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--

local bin = require("bin")
local nmap = require("nmap")
local stdnse = require("stdnse")
_ENV = stdnse.module("rdp", stdnse.seeall)

Packet = {
	
	TPKT = {

		new = function(self, data)
			local o = { data = tostring(data), version = 3 }
			setmetatable(o, self)
			self.__index = self
			return o
		end,

		__tostring = function(self)
			return bin.pack(">CCSA",
				self.version,
				self.reserved or 0,
				(self.data and #self.data + 4 or 4),
				self.data
			)
		end,
			
		parse = function(data)
			local tpkt = Packet.TPKT:new()
			local pos

			pos, tpkt.version, tpkt.reserved, tpkt.length = bin.unpack(">CCS", data)
			pos, tpkt.data = bin.unpack("A" .. (#data - pos), data, pos)
			return tpkt
		end
	},
	
	ITUT = {
		
		new = function(self, code, data)
			local o = { data = tostring(data), code = code }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		parse = function(data)
			local itut = Packet.ITUT:new()
			local pos

			pos, itut.length, itut.code = bin.unpack("CC", data)
			
			if ( itut.code == 0xF0 ) then
				pos, itut.eot = bin.unpack("C", data, pos)
			elseif ( itut.code == 0xD0 ) then
				pos, itut.dstref, itut.srcref, itut.class = bin.unpack(">SSC", data, pos)
			end
			
			pos, itut.data = bin.unpack("A" .. (#data - pos), data, pos)
			return itut
		end,
		
		__tostring = function(self)
			local len = (self.code ~= 0xF0 and #self.data + 1 or 2)
			local data = bin.pack("CC",
				len,
				self.code or 0
			)
			
			if ( self.code == 0xF0 ) then
				data = data .. bin.pack("C", 0x80) -- EOT
			end
			
			return data .. self.data
		end,
		
	},
	
}

Request = {
		
	ConnectionRequest = {
		
		new = function(self, proto)
			local o = { proto = proto }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
			
		__tostring = function(self)
			local cookie = "mstshash=nmap"
			local itpkt_len = 21 + #cookie
			local itut_len = 16 + #cookie
						
			local data = bin.pack(">SSCA",
				0x0000, -- dst reference
				0x0000, -- src reference
				0x00, -- class and options
				("Cookie: %s\r\n"):format(cookie))

			if ( self.proto ) then
				data = data .. bin.pack("<II",
					0x00080001, -- Unknown
					self.proto -- protocol
				)
			end
			return tostring(Packet.TPKT:new(Packet.ITUT:new(0xE0, data)))
		end
	},
	
	MCSConnectInitial = {
		
		new = function(self, cipher)
			local o = { cipher = cipher }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		__tostring = function(self)
		
			local data = bin.pack("<HIH",
				"7f 65" .. -- BER: Application-Defined Type = APPLICATION 101,
				"82 01 90" .. -- BER: Type Length = 404 bytes
				"04 01 01" .. -- Connect-Initial::callingDomainSelector
				"04 01 01" .. -- Connect-Initial::calledDomainSelector
				"01 01 ff" .. -- Connect-Initial::upwardFlag = TRUE
				"30 19" .. -- Connect-Initial::targetParameters (25 bytes)
				"02 01 22" .. -- DomainParameters::maxChannelIds = 34
				"02 01 02" .. -- DomainParameters::maxUserIds = 2
				"02 01 00" .. -- DomainParameters::maxTokenIds = 0
				"02 01 01" .. -- DomainParameters::numPriorities = 1
				"02 01 00" .. -- DomainParameters::minThroughput = 0
				"02 01 01" .. -- DomainParameters::maxHeight = 1
				"02 02 ff ff" .. -- DomainParameters::maxMCSPDUsize = 65535
				"02 01 02" .. -- DomainParameters::protocolVersion = 2
				"30 19" .. -- Connect-Initial::minimumParameters (25 bytes)
				"02 01 01" .. -- DomainParameters::maxChannelIds = 1
				"02 01 01" .. -- DomainParameters::maxUserIds = 1
				"02 01 01" .. -- DomainParameters::maxTokenIds = 1
				"02 01 01" .. -- DomainParameters::numPriorities = 1
				"02 01 00" .. -- DomainParameters::minThroughput = 0
				"02 01 01" .. -- DomainParameters::maxHeight = 1
				"02 02 04 20" .. -- DomainParameters::maxMCSPDUsize = 1056
				"02 01 02" .. -- DomainParameters::protocolVersion = 2
				"30 1c" .. -- Connect-Initial::maximumParameters (28 bytes)
				"02 02 ff ff" .. -- DomainParameters::maxChannelIds = 65535
				"02 02 fc 17" .. -- DomainParameters::maxUserIds = 64535
				"02 02 ff ff" .. -- DomainParameters::maxTokenIds = 65535
				"02 01 01" .. -- DomainParameters::numPriorities = 1
				"02 01 00" .. -- DomainParameters::minThroughput = 0
				"02 01 01" .. -- DomainParameters::maxHeight = 1
				"02 02 ff ff" .. -- DomainParameters::maxMCSPDUsize = 65535
				"02 01 02" .. -- DomainParameters::protocolVersion = 2
				"04 82 01 2f" .. -- Connect-Initial::userData (307 bytes)
				"00 05" .. -- object length = 5 bytes
				"00 14 7c 00 01" .. -- object
				"81 26" .. -- ConnectData::connectPDU length = 298 bytes 
				"00 08 00 10 00 01 c0 00 44 75 63 61 81 18" .. -- PER encoded (ALIGNED variant of BASIC-PER) GCC Conference Create Request PDU
				"01 c0 d4 00" .. -- TS_UD_HEADER::type = CS_CORE (0xc001), length = 216 bytes
				"04 00 08 00" .. -- TS_UD_CS_CORE::version = 0x0008004
				"00 05" .. -- TS_UD_CS_CORE::desktopWidth = 1280
				"20 03" .. -- TS_UD_CS_CORE::desktopHeight = 1024
				"01 ca" .. -- TS_UD_CS_CORE::colorDepth = RNS_UD_COLOR_8BPP (0xca01)
				"03 aa" .. -- TS_UD_CS_CORE::SASSequence
				"09 08 00 00" .. -- TS_UD_CS_CORE::keyboardLayout = 0x409 = 1033 = English (US)
				"28 0a 00 00" .. -- TS_UD_CS_CORE::clientBuild = 3790 
				"45 00 4d 00 50 00 2d 00 4c 00 41 00 50 00 2d 00 30 00 30 00 31 00 34 00 00 00 00 00 00 00 00 00" .. -- TS_UD_CS_CORE::clientName = ELTONS-TEST2
				"04 00 00 00" .. -- TS_UD_CS_CORE::keyboardType
				"00 00 00 00" .. -- TS_UD_CS_CORE::keyboardSubtype
				"0c 00 00 00" .. -- TS_UD_CS_CORE::keyboardFunctionKey
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " .. 
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " ..
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " ..
				"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " .. -- TS_UD_CS_CORE::imeFileName = ""
				"01 ca" .. -- TS_UD_CS_CORE::postBeta2ColorDepth = RNS_UD_COLOR_8BPP (0xca01)
				"01 00" .. -- TS_UD_CS_CORE::clientProductId
				"00 00 00 00" .. -- TS_UD_CS_CORE::serialNumber
				"10 00" .. -- TS_UD_CS_CORE::highColorDepth = 24 bpp
				"07 00" .. -- TS_UD_CS_CORE::supportedColorDepths
				"01 00" .. -- TS_UD_CS_CORE::earlyCapabilityFlags
				"36 00 39 00 37 00 31 00 32 00 2d 00 37 00 38 00 " ..
				"33 00 2d 00 30 00 33 00 35 00 37 00 39 00 37 00 " ..
				"34 00 2d 00 34 00 32 00 37 00 31 00 34 00 00 00 " ..
				"00 00 00 00 00 00 00 00 00 00 00 00 " .. -- TS_UD_CS_CORE::clientDigProductId = "69712-783-0357974-42714"
				"00" .. -- TS_UD_CS_CORE::connectionType = 0 (not used as RNS_UD_CS_VALID_CONNECTION_TYPE not set)
				"00" .. -- TS_UD_CS_CORE::pad1octet
				"00 00 00 00" .. -- TS_UD_CS_CORE::serverSelectedProtocol
				"04 c0 0c 00" .. -- TS_UD_HEADER::type = CS_CLUSTER (0xc004), length = 12 bytes
				"09 00 00 00" .. -- TS_UD_CS_CLUSTER::Flags = 0x0d
				"00 00 00 00" .. -- TS_UD_CS_CLUSTER::RedirectedSessionID
				"02 c0 0c 00", -- TS_UD_HEADER::type = CS_SECURITY (0xc002), length = 12 bytes
				-- "1b 00 00 00" .. -- TS_UD_CS_SEC::encryptionMethods
				self.cipher or 0,
				"00 00 00 00" .. -- TS_UD_CS_SEC::extEncryptionMethods
				"03 c0 2c 00" .. -- TS_UD_HEADER::type = CS_NET (0xc003), length = 44 bytes
				"03 00 00 00" .. -- TS_UD_CS_NET::channelCount = 3
				"72 64 70 64 72 00 00 00" .. -- CHANNEL_DEF::name = "rdpdr"
				"00 00 80 80" .. -- CHANNEL_DEF::options = 0x80800000
				"63 6c 69 70 72 64 72 00" .. -- CHANNEL_DEF::name = "cliprdr"
				"00 00 a0 c0" .. -- CHANNEL_DEF::options = 0xc0a00000
				"72 64 70 73 6e 64 00 00" .. -- CHANNEL_DEF::name = "rdpsnd" 
				"00 00 00 c0" -- CHANNEL_DEF::options = 0xc0000000
			)
			return tostring(Packet.TPKT:new(Packet.ITUT:new(0xF0, data)))
		end
		
		
		
	}
	
}

Response = {
	
	ConnectionConfirm = {
	
		new = function(self)
			local o = { }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		parse = function(data)
			local cc = Response.ConnectionConfirm:new()
			local pos, _
			
			cc.tpkt = Packet.TPKT.parse(data)
			cc.itut = Packet.ITUT.parse(cc.tpkt.data)			
			return cc
		end,
		
	},
	
	MCSConnectResponse = {
		new = function(self)
			local o = { }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		parse = function(data)
			local cr = Response.MCSConnectResponse:new()
			
			cr.tpkt = Packet.TPKT.parse(data)
			cr.itut = Packet.ITUT.parse(cr.tpkt.data)
			return cr
		end
	}
	
}

Comm = {
	
	-- Creates a new Comm instance
	-- @param host table
	-- @param port table
	-- @return o instance of Comm
	new = function(self, host, port)
		local o = { host = host, port = port }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- Connect to the server
	-- @return status true on success, false on failure
	-- @return err string containing error message, if status is false
	connect = function(self)
		self.socket = nmap.new_socket()
		self.socket:set_timeout(5000)
		if ( not(self.socket:connect(self.host, self.port)) ) then
			return false, "Failed connecting to server"
		end
		return true
	end,
	
	-- Close the connection to the server
	-- @return status true on success, false on failure
	close = function(self)
		return self.socket:close()
	end,
	
	-- Sends a message to the server
	-- @param pkt an instance of Request.*
	-- @return status true on success, false on failure
	-- @return err string containing error message, if status is false
	send = function(self, pkt)
		return self.socket:send(tostring(pkt))
	end,

	-- Receives a message from the server
	-- @return status true on success, false on failure
	-- @return err string containing error message, if status is false
	recv = function(self)
		return self.socket:receive()
	end,
	
	-- Sends a message to the server and receives the response
	-- @param pkt an instance of Request.*
	-- @return status true on success, false on failure
	-- @return err string containing error message, if status is false
	--         pkt instance of Response.* on success
	exch = function(self, pkt)
		local status, err = self:send(pkt)
		if ( not(status) ) then
			return false, err
		end

		local data
		status, data = self:recv()
		if ( #data< 5 ) then
			return false, "Packet too short"
		end

		local pos, itut_code = bin.unpack("C", data, 6)
		if ( itut_code == 0xD0 ) then
			stdnse.print_debug(2, "RDP: Received ConnectionConfirm response")
			return true, Response.ConnectionConfirm.parse(data)
		elseif ( itut_code == 0xF0 ) then
			return true, Response.MCSConnectResponse.parse(data)
		end		
		return false, "Received unhandled packet"
	end,
}

return _ENV;
