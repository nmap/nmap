--- A minimalistic PPPoE (Point-to-point protocol over Ethernet)
-- library, implementing basic support for PPPoE
-- Discovery and Configuration requests. The PPPoE protocol is ethernet based
-- and hence does not use any IPs or port numbers. 
--
-- The library contains a number of classes to support packet creation,
-- parsing and sending/receiving responses. The classes are:
--   o LCP   - Contains classes to build and parse PPPoE LCP requests and
--             responses.
--
--   o PPPoE - Contains classes to build and parse PPPoE requests and
--             responses.
--
--   o Comm  - Contains some basic functions for sending and receiving
--             LCP and PPPoE requests and responses.
--
--   o Helper- The Helper class serves as the main interface between scripts
--             and the library.
--
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("pppoe", stdnse.seeall)


EtherType = {
	PPPOE_DISCOVERY = 0x8863,
	PPPOE_SESSION = 0x8864,	
}

-- A Class to handle the Link Control Protocol LCP
LCP = {
	
	ConfigOption = {
		
		RESERVED 	= 0,
		MRU 		= 1,
		AUTH_PROTO 	= 3,
		QUAL_PROTO	= 4,
		MAGIC_NUMBER= 5,
		PROTO_COMPR	= 7,
		ACFC		= 8,

		-- Value has already been encoded, treat it as a byte stream
		RAW 		= -1,
		
		-- Creates a new config option
		-- @param option number containing the configuration option
		-- @param value containing the configuration option value
		-- @param raw string containing the configuration options raw value
		-- @return o new instance of ConfigOption
		new = function(self, option, value, raw)
			local o = {
				option = option,
				value = value,
				raw = raw,
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the ConfigOption
		-- class
		-- @param data string containing raw bytes to parse
		-- @return o instance of ConfigOption
		parse = function(data)
			local opt, pos, len = {}, 1, 0
			pos, opt.option, len = bin.unpack("CC", data, pos)
			pos, opt.raw = bin.unpack("A" .. ( len - 2 ), data, pos)
			
			-- MRU
			if ( 1 == opt.option ) then
				opt.value = select(2, bin.unpack(">S", opt.raw))
			end
			return LCP.ConfigOption:new(opt.option, opt.value, opt.raw)
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			-- MRU
			if ( self.raw ) then
				return bin.pack(">CCA", self.option, #self.raw + 2, self.raw )
			elseif( 1 == self.option ) then
				return bin.pack(">CCS", 1, 4, self.value)
			else
				error( ("Unsupported configuration option %d"):format(self.option) )
			end
		end,
	},
	
	-- A class to hold multiple ordered config options
	ConfigOptions = {
		
		new = function(self, options)
			local o = {
				options = options or {},
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Adds a new config option to the table
		-- @param option instance of ConfigOption
		add = function(self, option)
			table.insert(self.options, option)
		end,
		
		-- Gets a config option by ID
		-- @param opt number containing the configuration option to retrieve
		-- @return v instance of ConfigOption
		getById = function(self, opt)
			for _, v in ipairs(self.options) do
				if ( v.option == opt ) then
					return v
				end
			end
		end,
		
		-- Returns all config options in an ordered table
		-- @return tab table containing all configuration options
		getTable = function(self)
			local tab = {}
			for _, v in ipairs(self.options) do
				table.insert(tab, v)
			end
			return tab
		end,
		
		
		-- Parses a byte stream and builds a new instance of the ConfigOptions
		-- class
		-- @param data string containing raw bytes to parse
		-- @return o instance of ConfigOption
		parse = function(data)
			local options = LCP.ConfigOptions:new()
			local pos, opt, opt_val, len

			repeat
				pos, opt, len = bin.unpack(">CC", data, pos)
				if ( 0 == opt ) then break end			
				pos, opt_val = bin.unpack("A"..len, data, (pos - 2))
				options:add(LCP.ConfigOption.parse(opt_val))
			until( pos == #data )
			return options
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			local str = ""
			for _, v in ipairs(self.options) do
				str = str .. tostring(v)
			end
			return str
		end,
		
	},
	
	ConfigOptionName = {
		[0] = "Reserved",
		[1] = "Maximum receive unit",
		[3] = "Authentication protocol",
		[4] = "Quality protocol",
		[5] = "Magic number",
		[7] = "Protocol field compression",
		[8] = "Address and control field compression",
	},
	
	Code = {
		CONFIG_REQUEST 		= 1,
		CONFIG_ACK			= 2,
		CONFIG_NAK			= 3,
		TERMINATE_REQUEST	= 5,
		TERMINATE_ACK		= 6,
	},
	
	-- The LCP Header
	Header = {
		
		-- Creates a new instance of the LCP header
		-- @param code number containing the LCP code of the request
		-- @param identifier number containing the LCP identifier
		new = function(self, code, identifier)
			local o = {
				code = code,
				identifier = identifier or 1,
				length = 0,
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,


		-- Parses a byte stream and builds a new instance of the Header class
		-- @param data string containing raw bytes to parse
		-- @return o instance of ConfigOption
		parse = function(data)
			local header = LCP.Header:new()
			local pos
			pos, header.code, header.identifier, header.length = bin.unpack(">CCS", data)
			return header
		end,

		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			return bin.pack(">CCS", self.code, self.identifier, self.length)
		end,
		
	},
		
	ConfigRequest = {
		
		-- Creates a new instance of the ConfigRequest class
		-- @param identifier number containing the LCP identifier
		-- @param options table of <code>LCP.ConfigOption</code> options
		-- @return o instance of ConfigRequest
		new = function(self, identifier, options)
			local o = {
				header = LCP.Header:new(LCP.Code.CONFIG_REQUEST, identifier),
				options = LCP.ConfigOptions:new(options)
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the ConfigRequest
		-- class
		-- @param data string containing raw bytes to parse
		-- @return o instance of ConfigRequest
		parse = function(data)
			local req = LCP.ConfigRequest:new()
			req.header = LCP.Header.parse(data)
			req.options = LCP.ConfigOptions.parse(data:sub(#tostring(req.header) + 1))
			return req
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			self.header.length = 4 + #tostring(self.options)
			return tostring(self.header) .. tostring(self.options)
		end,
	},
	
	ConfigNak = {
		
		-- Creates a new instance of the ConfigNak class
		-- @param identifier number containing the LCP identifier
		-- @param options table of <code>LCP.ConfigOption</code> options
		-- @return o instance of ConfigNak
		new = function(self, identifier, options)
			local o = {
				header = LCP.Header:new(LCP.Code.CONFIG_NAK, identifier),
				options = LCP.ConfigOptions:new(options),
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			self.header.length = 4 + #tostring(self.options)
			return tostring(self.header) .. tostring(self.options)
		end,
	},
	
	ConfigAck = {
		
		-- Creates a new instance of the ConfigAck class
		-- @param identifier number containing the LCP identifier
		-- @param options table of <code>LCP.ConfigOption</code> options
		-- @return o instance of ConfigNak
		new = function(self, identifier, options)
			local o = {
				header = LCP.Header:new(LCP.Code.CONFIG_ACK, identifier),
				options = LCP.ConfigOptions:new(options),
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the ConfigAck class
		-- @param data string containing raw bytes to parse
		-- @return o instance of ConfigRequest
		parse = function(data)
			local ack = LCP.ConfigAck:new()
			ack.header = LCP.Header.parse(data)
			ack.options = LCP.ConfigOptions.parse(data:sub(#tostring(ack.header) + 1))
			return ack
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			self.header.length = 4 + #tostring(self.options)
			return tostring(self.header) .. tostring(self.options)
		end,
		
	},
	
	TerminateRequest = {

		-- Creates a new instance of the TerminateRequest class
		-- @param identifier number containing the LCP identifier
		-- @return o instance of ConfigNak	
		new = function(self, identifier, data)
			local o = {
				header = LCP.Header:new(LCP.Code.TERMINATE_REQUEST, identifier),
				data = data or "",
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the class instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			self.header.length = 4 + #self.data
			return tostring(self.header) .. self.data
		end,
	}
	
}

-- The PPPoE class
PPPoE = {
	
	-- Supported PPPoE codes (requests/responses)
	Code = {
		SESSION_DATA	= 0x00,
		PADO 			= 0x07,
		PADI 			= 0x09,
		PADR 			= 0x19,
		PADS 			= 0x65,	
		PADT			= 0xa7,	
	},
	
	-- Support PPPoE Tag types
	TagType = {
		SERVICE_NAME	= 0x0101,
		AC_NAME			= 0x0102,
		HOST_UNIQUE 	= 0x0103,
		AC_COOKIE		= 0x0104,
	},
	
	-- Table used to convert table IDs to Names
	TagName = {
		[0x0101] = "Service-Name",
		[0x0102] = "AC-Name",
		[0x0103] = "Host-Uniq",
		[0x0104] = "AC-Cookie",
	},
	
		
	Header = {
		
		-- Creates a new instance of the PPPoE header class
		-- @param code number containing the PPPoE code
		-- @param session number containing the PPPoE session
		-- @return o instance of Header	
		new = function(self, code, session)
			local o = {
				version = 1,
				type = 1,
				code = code,
				session = session or 0,
				length = 0,
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the class
		-- @param data string containing raw bytes to parse
		-- @return o instance of Header
		parse = function(data)
			local pos, vertyp
			local header = PPPoE.Header:new()
			pos, vertyp, header.code, header.session, header.length = bin.unpack(">CCSS", data)
			header.version = bit.rshift(vertyp,4)
			header.type = bit.band(vertyp, 0x0F)		
			return header
		end,
		
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			local vertype = bit.lshift(self.version, 4) + self.type
			return bin.pack(">CCSS", vertype, self.code, self.session, self.length)
		end,
		
		
	},
	
	-- The TAG NVP Class
	Tag = {		
		
		-- Creates a new instance of the Tag class
		-- @param tag number containing the tag type
		-- @param value string/number containing the tag value
		-- @return o instance of Tag	
		new = function(self, tag, value)
			local o = { tag = tag, value = value or "" }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
			
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			return bin.pack(">SSA", self.tag, #self.value, self.value)
		end,
	},
		
	PADI = {
		
		-- Creates a new instance of the PADI class
		-- @param tags table of <code>PPPoE.Tag</code> instances
		-- @param value string/number containing the tag value
		-- @return o instance of ConfigNak	
		new = function(self, tags)
			local c = ""
			for i=1, 4 do
				c = c .. math.random(255)
			end
			
			local o = {
				header = PPPoE.Header:new(PPPoE.Code.PADI),
				tags = tags or { 
					PPPoE.Tag:new(PPPoE.TagType.SERVICE_NAME),
					PPPoE.Tag:new(PPPoE.TagType.HOST_UNIQUE,  bin.pack("A", c))
				}
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			local tags = ""
			for _, tag in ipairs(self.tags) do
				tags = tags .. tostring(tag)
			end
			self.header.length = #tags
			return tostring(self.header) .. tags
		end,
		
	},
	
	PADO = {
	
		-- Creates a new instance of the PADO class
		-- @return o instance of PADO	
		new = function(self)
			local o = { tags = {} }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the class
		-- @param data string containing raw bytes to parse
		-- @return o instance of PADO
		parse = function(data)
			local pado = PPPoE.PADO:new()
			pado.header = PPPoE.Header.parse(data)
			local pos = #tostring(pado.header) + 1
			pado.data = data:sub(pos)
			
			repeat
				local tag, len, decoded, raw
				pos, tag, len = bin.unpack(">SS", data, pos)
				raw = select(2, bin.unpack("A" .. len, data, pos))
				if ( PPPoE.TagDecoder[tag] ) then
					pos, decoded = PPPoE.TagDecoder[tag](data, pos, len)
				else
					stdnse.print_debug("PPPoE: Unsupported tag (%d)", tag)
					pos = pos + len
				end
				local t = PPPoE.Tag:new(tag, raw)
				t.decoded = decoded
				table.insert(pado.tags, t)
			until( pos >= #data )
			
			return pado
		end,
	},
	
	PADR = {
		
		-- Creates a new instance of the PADR class
		-- @param tags table of <code>PPPoE.Tag</code> instances
		-- @return o instance of PADR	
		new = function(self, tags)
			local o = { 
				tags = tags or {},
				header = PPPoE.Header:new(PPPoE.Code.PADR)
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			local tags = ""
			for _, tag in ipairs(self.tags) do
				tags = tags .. tostring(tag)
			end
			self.header.length = #tags
			return tostring(self.header) .. tags
		end,
		
	},
	
	PADS = {
		
		-- Creates a new instance of the PADS class
		-- @return o instance of PADS	
		new = function(self)
			local o = { tags = {} }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the class
		-- @param data string containing raw bytes to parse
		-- @return o instance of PADS
		parse = function(data)
			local pads = PPPoE.PADS:new()
			pads.header = PPPoE.Header.parse(data)
			local pos = #tostring(pads.header) + 1
			pads.data = data:sub(pos)
			return pads
		end,

	},
	
	PADT = {
		
		-- Creates a new instance of the PADT class
		-- @param session number containing the PPPoE session
		-- @return o instance of PADT	
		new = function(self, session)
			local o = { header = PPPoE.Header:new(PPPoE.Code.PADT) }
			setmetatable(o, self)
			o.header.session = session
			self.__index = self
			return o
		end,
	
		-- Parses a byte stream and builds a new instance of the class
		-- @param data string containing raw bytes to parse
		-- @return o instance of PADI
		parse = function(data)
			local padt = PPPoE.PADT:new()
			padt.header = PPPoE.Header.parse(data)
			return padt
		end,
		
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			return tostring(self.header)
		end,
	},
	
	SessionData = {
		
		-- Creates a new instance of the SessionData class
		-- @param session number containing the PPPoE session
		-- @param data string containing the LCP data to send
		-- @return o instance of ConfigNak	
		new = function(self, session, data)
			local o = { 
				data = data or "",
				header = PPPoE.Header:new(PPPoE.Code.SESSION_DATA)
			}
			setmetatable(o, self)
			o.header.session = session
			self.__index = self
			return o
		end,
		
		-- Parses a byte stream and builds a new instance of the class
		-- @param data string containing raw bytes to parse
		-- @return o instance of SessionData
		parse = function(data)
			local sess = PPPoE.SessionData:new()
			sess.header = PPPoE.Header.parse(data)
			local pos = #tostring(sess.header) + 1 + 2
			sess.data = data:sub(pos)
			return sess
		end,
		
		-- Converts the instance to string
		-- @return string containing the raw config option
		__tostring = function(self)
			-- 2 for the encapsulation
			self.header.length = 2 + 4 + #self.data
			return tostring(self.header) .. bin.pack(">S", 0xC021) .. self.data
		end,
		
	}
	
	
}

-- A bunch of tag decoders
PPPoE.TagDecoder = {}
PPPoE.TagDecoder.decodeHex = function(data, pos, len) return pos + len, stdnse.tohex(data:sub(pos, pos+len)) end
PPPoE.TagDecoder.decodeStr = function(data, pos, len) return pos + len, data:sub(pos, pos + len - 1) end
PPPoE.TagDecoder[PPPoE.TagType.SERVICE_NAME]= PPPoE.TagDecoder.decodeStr		
PPPoE.TagDecoder[PPPoE.TagType.AC_NAME] 	= PPPoE.TagDecoder.decodeStr
PPPoE.TagDecoder[PPPoE.TagType.AC_COOKIE] 	= PPPoE.TagDecoder.decodeHex
PPPoE.TagDecoder[PPPoE.TagType.HOST_UNIQUE] = PPPoE.TagDecoder.decodeHex

-- The Comm class responsible for communication with the PPPoE server
Comm = {
	
	-- Creates a new instance of the Comm class
	-- @param iface string containing the interface name
	-- @param src_mac string containing the source MAC address
	-- @param dst_mac string containing the destination MAC address
	-- @return o new instance of Comm
	new = function(self, iface, src_mac, dst_mac)
		local o = {
			iface = iface,
			src_mac = src_mac,
			dst_mac = dst_mac,
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- Sets up the pcap receiving socket
	-- @return status true on success
	connect = function(self)
		self.socket = nmap.new_socket()
		self.socket:set_timeout(10000)
		
		-- there's probably a more elegant way of doing this
		local mac = {}
		for i=1, #self.src_mac do table.insert(mac, select(2,bin.unpack("H", self.src_mac, i))) end
		mac = stdnse.strjoin(":", mac)
		
		-- let's set a filter on PPPoE we can then check what packet is ours, 
		-- based on the HOST_UNIQUE tag, if we need to
		self.socket:pcap_open(self.iface, 1500, false, "ether[0x0c:2] == 0x8863 or ether[0x0c:2] == 0x8864 and ether dst " .. mac)	
		return true
	end,
	
	-- Sends a packet
	-- @param data class containing the request to send
	-- @return status true on success, false on failure
	send = function(self, data)
		local eth_type = ( data.header.code == PPPoE.Code.SESSION_DATA ) and 0x8864 or 0x8863
		local ether = bin.pack(">AAS", self.dst_mac, self.src_mac, eth_type)
		local p = packet.Frame:new(ether .. tostring(data))
				
		local sock = nmap.new_dnet()
		if ( not(sock) ) then
			return false, "Failed to create raw socket"
		end
		
		local status = sock:ethernet_open(self.iface)
		-- we don't actually need to do this as the script simply crashes
		-- if we don't have the right permissions at this point
		if ( not(status) ) then
			return false, "Failed to open raw socket"
		end

		status = sock:ethernet_send(p.frame_buf)
		if ( not(status) ) then
			return false, "Failed to send data"
		end
		sock:ethernet_close()
		return true	
	end,
	
	-- Receive a response from the server
	-- @return status true on success, false on failure
	-- @return response class containing the response or
	--         err string on error
	recv = function(self)
		local status, _, l2, l3 = self.socket:pcap_receive()
		-- if we got no response, just return false as there's
		-- probably not really an error
		if ( not(status) ) then
			return false
		end
		
		local header = PPPoE.Header.parse(l3)
		local p = packet.Frame:new(l2..l3)
	
		-- there's probably a more elegant way of doing this
		if ( EtherType.PPPOE_DISCOVERY == p.ether_type ) then
			if ( header.code == PPPoE.Code.PADO ) then
				local pado = PPPoE.PADO.parse(l3)
				pado.mac_srv = p.mac_src
				return true, pado
			elseif ( header.code == PPPoE.Code.PADS ) then
				local pads = PPPoE.PADS.parse(l3)
				return true, pads
			elseif ( header.code == PPPoE.Code.PADT ) then
				local pads = PPPoE.PADT.parse(l3)
				return true, pads
			end
		elseif ( EtherType.PPPOE_SESSION == p.ether_type ) then
			return true, PPPoE.SessionData.parse(l3)
		end
		return false, ("Received unsupported response, can't decode code (%d)"):format(header.code)
	end,
	
	-- Does an "exchange", ie, sends a request and waits for a response
	-- @param data class containing the request to send
	-- @return status true on success, false on failure
	-- @return response class containing the response or
	--         err string on error
	exch = function(self, data)				
		local status, err = self:send(data)
		if ( not(status) ) then
			return false, err
		end
		local retries, resp = 3, nil
		
		repeat
			status, resp = self:recv()
			if ( data.header and 0 == data.header.session ) then
				return true, resp
			elseif ( data.header and data.header.session == resp.header.session ) then
				return true, resp
			end
			retries = retries - 1
		until(retries == 0)
		
		return false, "Failed to retrieve proper PPPoE response"
	end,
	
}

-- The Helper class is the main script interface
Helper = {
	
	-- Creates a new instance of Helper
	-- @param iface string containing the name of the interface to use
	-- @return o new instance on success, nil on failure
	new = function(self, iface)
		local o = {
			iface = iface,

			-- set the LCP identifier to 0
			identifier = 0,
		}
		setmetatable(o, self)
		self.__index = self
		
		if ( not(nmap.is_privileged()) ) then
			return nil, "The PPPoE library requires Nmap to be run in privileged mode"
		end
		
		-- get src_mac
		local info = nmap.get_interface_info(iface)
		if ( not(info) or not(info.mac) ) then
			return nil, "Failed to get source MAC address"
		end
		o.comm = Comm:new(iface, info.mac)
		return o
	end,
	
	-- Sets up the pcap socket for listening and does some other preparations
	-- @return status true on success, false on failure
	connect = function(self)
		return self.comm:connect()
	end,
		
	
	-- Performs a PPPoE discovery initiation by sending a PADI request to the
	-- ethernet broadcast address
	-- @return status true on success, false on failure
	-- @return pado instance of PADO on success, err string on failure
	discoverInit = function(self)
		local padi = PPPoE.PADI:new()
		self.comm.dst_mac = bin.pack("H", "FF FF FF FF FF FF")
		local status, err = self.comm:send(padi)
		if ( not(status) ) then
			return false, err
		end
		-- wait for a pado
		local pado, retries = nil, 3
		
		repeat
			status, pado = self.comm:recv()
			if ( not(status) ) then
				return status, pado
			end	
			retries = retries - 1
		until( pado.tags or retries == 0 )
		if ( not(pado.tags) ) then
			return false, "PADO response containined no tags"
		end

		local pado_host_unique
		for _, tag in ipairs(pado.tags) do
			if ( PPPoE.TagType.HOST_UNIQUE == tag.tag ) then
				pado_host_unique = tag.raw
			end
		end
		
		-- store the tags for later use
		self.tags = pado.tags
		self.comm.dst_mac = pado.mac_srv

		if ( pado_host_unique and
			 pado_host_unique ~= padi.tags[PPPoE.TagType.HOST_UNIQUE] ) then
			-- currently, we don't handle this, we probably should
			-- in order to do so, we need to split the function exch
			-- to recv and send
			return false, "Got incorrect answer"
		end

		return true, pado
	end,
	
	-- Performs a Discovery Request by sending PADR to the PPPoE ethernet
	-- address
	-- @return status true on success, false on failure
	-- @return pads instance of PADS on success
	discoverRequest = function(self)
	
		-- remove the AC-Name tag if there is one
		local function getTag(tag)
			for _, t in ipairs(self.tags) do
				if ( tag == t.tag ) then
					return t
				end
			end
		end
		
		local taglist = { 
			PPPoE.TagType.SERVICE_NAME,
			PPPoE.TagType.HOST_UNIQUE,
			PPPoE.TagType.AC_COOKIE
		}
	
		local tags = {}
		for _, t in ipairs(taglist) do
			if ( getTag(t) ) then
				table.insert(tags, getTag(t))
			end
		end
	
		local padr = PPPoE.PADR:new(tags)
		local status, pads = self.comm:exch(padr)

		if ( status ) then
			self.session = pads.header.session
		end

		return status, pads
	end,

	-- Attempts to specify a method for authentication
	-- If the server responds with another method it's NAK:ed and we try to set
	-- our requested method instead. If this fails, we return a failure
	-- @param method string containing one of the following methods:
	--        <code>MSCHAPv1</code>, <code>MSCHAPv2</code> or <code>PAP</code>
	-- @return status true on success, false on failure
	--         err string containing error message on failure
	setAuthMethod = function(self, method)

		local AuthMethod = {
			methods = {
				{ name = "EAP", value = bin.pack("H", "C227") },
				{ name = "MSCHAPv1", value = bin.pack("H", "C22380") },
				{ name = "MSCHAPv2", value = bin.pack("H", "C22381") },
				{ name = "PAP", value = bin.pack("H", "C023") },
			}
		}

		AuthMethod.byName = function(name)
			for _, m in ipairs(AuthMethod.methods) do
				if ( m.name == name ) then
					return m
				end
			end
		end
		
		AuthMethod.byValue = function(value)
			for _, m in ipairs(AuthMethod.methods) do
				if ( m.value == value ) then
					return m
				end
			end
		end
		
		local auth_data = ( AuthMethod.byName(method) and AuthMethod.byName(method).value )
		if ( not(auth_data) ) then
			return false, ("Unsupported authentication mode (%s)"):format(method)
		end
		
		self.identifier = self.identifier + 1
		
		-- First do a Configuration Request
		local options = { LCP.ConfigOption:new(LCP.ConfigOption.MRU, 1492) }
		local lcp_req = LCP.ConfigRequest:new(self.identifier, options)
		local sess_req = PPPoE.SessionData:new(self.session, tostring(lcp_req))
		local status, resp = self.comm:exch(sess_req)
		
		if ( not(status) or PPPoE.Code.SESSION_DATA ~= resp.header.code ) then
			return false, "Unexpected packet type was received"
		end
		
		-- Make sure we got a Configuration Request in return
		local lcp_header = LCP.Header.parse(resp.data)				
		if ( LCP.Code.CONFIG_REQUEST ~= lcp_header.code ) then
			return false, ("Unexpected packet type was received (%d)"):format(lcp_header.code)
		end
			
		local config_req = LCP.ConfigRequest.parse(resp.data)
		if ( not(config_req.options) ) then
			return false, "Failed to retrieve any options from response"
		end
		
		local auth_proposed = config_req.options:getById(LCP.ConfigOption.AUTH_PROTO)
				
		if ( auth_proposed.raw ~= auth_data ) then
			local options = { LCP.ConfigOption:new(LCP.ConfigOption.AUTH_PROTO, nil, bin.pack("A", auth_data)) }
			local lcp_req = LCP.ConfigNak:new(self.identifier, options)
			local sess_req = PPPoE.SessionData:new(self.session, tostring(lcp_req))
			local status, resp = self.comm:exch(sess_req)
			
			if ( not(status) or PPPoE.Code.SESSION_DATA ~= resp.header.code ) then
				return false, "Unexpected packet type was received"
			end
			
			-- Make sure we got a Configuration Request in return
			local lcp_header = LCP.Header.parse(resp.data)				
			if ( LCP.Code.CONFIG_REQUEST ~= lcp_header.code ) then
				return false, ("Unexpected packet type was received (%d)"):format(lcp_header.code)
			end

			config_req = LCP.ConfigRequest.parse(resp.data)

			-- if the authentication methods match, send an ACK
			if ( config_req.options:getById(LCP.ConfigOption.AUTH_PROTO).raw == auth_data ) then
				-- The ACK is essential the Config Request, only with a different code
				-- Do a dirty attempt to just replace the code and send the request back as an ack
				self.identifier = self.identifier + 1
				
				local lcp_req = LCP.ConfigAck:new(config_req.header.identifier, config_req.options:getTable())
				local sess_req = PPPoE.SessionData:new(self.session, tostring(lcp_req))
				local status, resp = self.comm:send(sess_req)
				
				return true
			end
			
			return false, "Authentication method was not accepted"
		end


		return false, "Failed to negotiate authentication mechanism"
	end,
	
	-- Sends a LCP Terminate Request and waits for an ACK
	-- Attempts to do so 10 times before aborting
	-- @return status true on success false on failure
	close = function(self)
		local tries = 10		
		repeat
			if ( 0 == self.session ) then
				break
			end
			local lcp_req = LCP.TerminateRequest:new(self.identifier)
			local sess_req = PPPoE.SessionData:new(self.session, tostring(lcp_req))
			local status, resp = self.comm:exch(sess_req)
			if ( status and resp.header and resp.header.code ) then
				if ( PPPoE.Code.SESSION_DATA == resp.header.code ) then
					local lcp_header = LCP.Header.parse(resp.data) 
					if ( LCP.Code.TERMINATE_ACK == lcp_header.code ) then
						break
					end
				end
			end
			tries = tries - 1
		until( tries == 0 )	
		
		self.comm:exch(PPPoE.PADT:new(self.session))
		
		return true
	end,
	
}

return _ENV;
