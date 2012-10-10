---
-- TNS Library supporting a very limited subset of Oracle operations
--
-- Summary
-- -------
-- 	The library currently provides functionality to connect and authenticate
--  to the Oracle database server. Some preliminary query support has been
--  added, which only works against a few specific versions. The library has
--  been tested against and known to work with Oracle 10g and 11g. Please check
--  the matrix below for tested versions that are known to work. 
--
--  Due to the lack of documentation the library is based mostly on guesswork
--  with a lot of unknowns. Bug reports are therefore both welcome and
--  important in order to further improve this library. In addition, knowing
--  that the library works against versions not in the test matrix is valuable
--  as well.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--	 o Packet.*
--		- The Packet classes contain specific packets and function to serialize
--        them to strings that can be sent over the wire. Each class may also
--        contain a function to parse the servers response.
--
--   o Comm
--		- Implements a number of functions to handle communication 
--
--   o Crypt
-- 		- Implements encryption algorithms and functions to support 
--        authentication with Oracle 10G and Oracle 11G.
--
--   o Helper
--		- A helper class that provides easy access to the rest of the library
--
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
--	tnshelper 	= tns.Helper:new(host, port)
--	status, err = tnshelper:Connect()
--	status, res = tnshelper:Login("sys", "change_on_install")
--	status, err = tnshelper:Close()
-- </code>
--
-- Additional information
-- ----------------------
-- The implementation is based on the following documentation and through
-- analysis of packet dumps:
--
--  o Oracle 10g TNS AES-128 authentication details (Massimiliano Montoro)
--  	x http://www.oxid.it/downloads/oracle_tns_aes128_check.txt
--  o Oracle 11g TNS AES-192 authentication details (Massimiliano Montoro)
-- 		x http://www.oxid.it/downloads/oracle_tns_aes192_check.txt
--  o Initial analysis of Oracle native authentication version 11g
--    (László Tóth)
--      x http://www.soonerorlater.hu/index.khtml?article_id=512
--  o Oracle native authentication version 9i and 10g (László Tóth)
--      x http://www.soonerorlater.hu/index.khtml?article_id=511
--
-- This implementation is tested and known to work against Oracle 10g and 11g
-- on both Linux and Windows. For details regarding what versions where tested
-- please consult the matrix below.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
-- @args tns.sid specifies the Oracle instance to connect to

--
-- Version 0.71
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/21/2010 - v0.2 - made minor changes to support 11gR2 on Windows
-- Revised 07/23/2010 - v0.3 - corrected incorrect example code in docs
--                           - removed ssl require
-- Revised 02/08/2011 - v0.4 - added basic query support <patrik@cqure.net>
-- Revised 17/08/2011 - v0.5 - fixed bug that would prevent connections from
--                             working on 64-bit oracle.
-- Revised 20/08/2011 - v0.6 - fixed a few bugs in connection and query code
--                           - changed so that connections against untested
--                             databases versions will fail
--                           - added some more documentation and fixed some
--                             indentation bugs
--                             <patrik@cqure.net>
-- Revised 26/08/2011 - v0.7 - applied patch from Chris Woodbury
--                             <patrik@cqure.net>
-- Revised 28/08/2011 - v0.71- fixed a bug that would prevent the library from
--                             authenticating against Oracle 10.2.0.1.0 XE
--                             <patrik@cqure.net>
--
-- The following versions have been tested and are known to work:
-- +--------+---------------+---------+-------+-------------------------------+
-- | OS     | DB Version    | Edition | Arch  | Functionality                 |
-- +--------+---------------+---------+-------+-------------------------------|
-- | Win    | 10.2.0.1.0    | EE      | 32bit | Authentication                |
-- | Win    | 10.2.0.1.0    | XE      | 32bit | Authentication, Queries       |
-- | Linux  | 10.2.0.1.0    | EE      | 32bit | Authentication                |
-- | Win    | 11.1.0.6.0    | EE      | 32bit | Authentication, Queries       |
-- | Win    | 11.1.0.6.0    | EE      | 64bit | Authentication                |
-- | Win    | 11.2.0.1.0    | EE      | 64bit | Authentication                |
-- | Win    | 11.2.0.2.0    | EE      | 64bit | Authentication                |
-- | Linux  | 11.2.0.1.0    | EE      | 64bit | Authentication                |
-- | Win    | 11.2.0.2.0    | XE      | 32bit | Authentication, Queries       |
-- | Win    | 11.2.0.2.0    | EE      | 64bit | Authentication, Queries       |
-- +--------+---------------+---------+-------+-------------------------------+
--

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("tns", stdnse.seeall)

-- Oracle version constants
ORACLE_VERSION_10G = 313
ORACLE_VERSION_11G = 314

-- Data type to number conversions
DataTypes = {
	NUMBER = 2,
	DATE = 12,
}

-- A class containing some basic authentication options
AuthOptions = 
{
		
	-- Creates a new AuthOptions instance
	-- @return o new instance of AuthOptions
	new = function( self )
		local o = {
			auth_term = "pts/" .. math.random(255),
			auth_prog = ("sqlplus@nmap_%d (TNS V1-V3)"):format(math.random(32768)),
			auth_machine = "nmap_target",
			auth_pid = "" .. math.random(32768),
			auth_sid = "nmap_" .. math.random(32768)
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,	
	
}

-- Decodes different datatypes from the byte arrays or strings read from the
-- tns data packets
DataTypeDecoders = {
	
	-- Decodes a number
	[DataTypes.NUMBER] = function(val)
		if ( #val == 0 ) then return "" end
		if ( #val == 1 and val == '\128' ) then	return 0 end
		
		local bytes = {}
		for i=1, #val do bytes[i] = select(2, bin.unpack("C", val, i)) end
		
		local positive = ( bit.band(bytes[1], 0x80) ~= 0 )

		local function convert_bytes(bytes, positive)
			local ret_bytes = {}
			local len = #bytes

			if ( positive ) then
				ret_bytes[1] = bit.band(bytes[1], 0x7F) - 65
				for i=2, len do ret_bytes[i] = bytes[i] - 1 end
			else
				ret_bytes[1] = bit.band(bit.bxor(bytes[1], 0xFF), 0x7F) - 65
				for i=2, len do ret_bytes[i] = 101 - bytes[i] end
			end
			
			return ret_bytes
		end
		
		bytes = convert_bytes(bytes, positive)

		local k = ( #bytes - 1 > bytes[1] +1 ) and ( bytes[1] + 1 ) or #bytes - 1
		local l = 0
		for m=1, k do l = l * 100 + bytes[m+1] end
		for m=bytes[1]-#bytes - 1, 0, -1 do l = l * 100	end
		
		return (positive and l or -l)
	end,

	-- Decodes a date
	[DataTypes.DATE] = function(val)
		local bytes = {}
	
		if (#val == 0) then
			return ""
		elseif( #val ~= 7 ) then
			return "ERROR: Failed to decode date"
		end
	
		for i=1, 7 do bytes[i] = select(2, bin.unpack("C", val, i))	end

		return ("%d-%02d-%02d"):format( (bytes[1] - 100 ) * 100 + bytes[2] - 100, bytes[3], bytes[4] )
	end,
	
	
	
}

-- Packet class table
--
-- Each Packet type SHOULD implement:
-- 	o tns_type - A variable indicating the TNS Type of the Packet
--  o toString - A function that serializes the object to string
--
-- Each Packet MAY also optionally implement:
--  o parseResponse 
--     x An optional function that parses the servers response
--     x The function should return status and an undefined second return value
--
Packet = {}

-- Contains the TNS header and basic functions for decoding and reading the
-- TNS packet.
Packet.TNS = {

	checksum = 0,
	hdr_checksum = 0,
	length = 0,
	reserved = 0,

	Type = 
	{
		CONNECT = 1,
		ACCEPT = 2,
		REFUSE = 4,
		DATA = 6,
		RESEND = 11,
		MARKER = 12,
	},

	new = function( self, typ )
		local o = {
			type = typ
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Read a TNS packet of the socket
	--
	-- @return true on success, false on failure
	-- @return err string containing error message on failure
	recv = function( self )
		local status, data = self.socket:receive_buf( match.numbytes(2), true )

		if ( not(status) ) then
			return status, data
		end

		local _
		_, self.length = bin.unpack(">S", data )
		
		status, data = self.socket:receive_buf( match.numbytes(6), true )
		if ( not(status) ) then
			return status, data
		end
		
		_, self.checksum, self.type, self.reserved, self.hdr_checksum = bin.unpack(">SCCS", data)
		
		status, data = self.socket:receive_buf( match.numbytes(self.length - 8), true )
		if ( status ) then
			self.data = data
		end
		
		return true
	end,
	
	parse = function(data)
		local tns = Packet.TNS:new()
		local pos
		pos, tns.length, tns.checksum, tns.type, tns.reserved, tns.hdr_checksum = bin.unpack(">SSCCS", data)
		pos, tns.data = bin.unpack("A" .. ( tns.length - 8 ), data, pos)
		return tns
	end,
	
	--- Converts the TNS packet to string suitable to be sent over the socket
	--
	-- @return string containing the TNS packet
	__tostring = function( self )
		local data = bin.pack(">SSCCSA", self.length, self.checksum, self.type, self.reserved, self.hdr_checksum, self.data )
		return data
	end,
	
}

-- Initiates the connection to the listener
Packet.Connect = {
	
		CONN_STR = [[
					(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d))
					(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=%s)(CID=
					(PROGRAM=sqlplus)(HOST=%s)(USER=nmap))))]],
	
		version = 314,
		version_comp = 300,
		svc_options = 0x0c41,
		sess_dus = 8192,
		max_trans_dus = 32767,
		nt_proto_char = 0x7f08,
		line_turnaround = 0,
		value_of_1_in_hw = 0x0100,
		conn_data_len = 0,
		conn_data_offset = 58,
		conn_data_max_recv = 512,
		conn_data_flags_0 = 0x41,
		conn_data_flags_1 = 0x41,
		trace_cross_1 = 0,
		trace_cross_2 = 0,
		trace_unique_conn = 0,
		tns_type = Packet.TNS.Type.CONNECT,
		
		-- Creates a new Connect instance
		-- @param rhost string containing host or ip
		-- @param rport string containing the port number
		-- @param dbinstance string containing the instance name
		-- @return o containing new Connect instance
		new = function( self, rhost, rport, dbinstance )
			local o = {
				rhost = rhost,
				rport = rport,
				conn_data = Packet.Connect.CONN_STR:format( rhost, rport, dbinstance, rhost ),
				dbinstance = dbinstance:upper()
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		setCmd = function( self, cmd )
			local tmp = [[			
				(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=)(HOST=%s)(USER=nmap))(COMMAND=%s)(ARGUMENTS=64)(SERVICE=%s:%d)(VERSION=185599488)))
				]]
			self.conn_data = tmp:format( self.rhost, cmd, self.rhost, self.rport )
		end,
		
		--- Parses the server response from the CONNECT
		--
		-- @param tns Packet.TNS containing the TNS packet received from the
		--        server
		-- @return true on success, false on failure
		-- @return version number containing the version supported by the
		--         server or an error message on failure
		parseResponse = function( self, tns )
			local pos, version
			
			if ( tns.type ~= Packet.TNS.Type.ACCEPT ) then
				if ( tns.data:match("ERR=12514") ) then
					return false, ("TNS: The listener could not resolve \"%s\""):format(self.dbinstance)
				end
				return false, tns.data:match("%(ERR=(%d*)%)")
			end
			
			pos, version = bin.unpack(">S", tns.data )
			return true, version
		end,
		
		--- Converts the CONNECT packet to string
		--
		-- @return string containing the packet
		__tostring = function( self )
			self.conn_data_len = #self.conn_data

			return bin.pack(">SSSSSSSSSSICCIILLA", self.version, self.version_comp, self.svc_options,
				self.sess_dus, self.max_trans_dus, self.nt_proto_char,
				self.line_turnaround, self.value_of_1_in_hw, self.conn_data_len,
				self.conn_data_offset, self.conn_data_max_recv, self.conn_data_flags_0,
				self.conn_data_flags_1, self.trace_cross_1, self.trace_cross_2,
				self.trace_unique_conn, 0, self.conn_data )
		end,
			
	
}

-- A TNS data packet, one of the most common packets
Packet.Data = {

	flag = 0,

	-- Createas a new Data instance
	-- @return o new instance of Data
	new = function( self, data )
		local o = {
			TNS = Packet.TNS:new( Packet.TNS.Type.DATA ),
			data = data
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet
	__tostring = function( self )
		local data = bin.pack( ">S", self.flag ) .. self.data
		self.TNS.length = #data + 8
		return tostring(self.TNS) .. data
	end,
	
}

-- Packet received by the server to indicate errors or end of
-- communication.
Packet.Attention = {

	tns_type = Packet.TNS.Type.MARKER,

	-- Creates a new instance of the Attention packet
	-- @return o new instance of Attention
	new = function( self, typ, data )
		local o = { data = data, att_type = typ }
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	--- Converts the MARKER packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		return bin.pack( ">C", self.att_type ) .. self.data
	end,
		
}

-- Packet initializing challenge response authentication
Packet.PreAuth = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0,	
	param_order = { 
		{ ["AUTH_TERMINAL"] = "auth_term" },
		{ ["AUTH_PROGRAM_NM"] = "auth_prog" },
		{ ["AUTH_MACHINE"] = "auth_machine" },
		{ ["AUTH_PID"] = "auth_pid" },
		{ ["AUTH_SID"] = "auth_sid" }
	},
	
	--- Creates a new PreAuth packet
	--
	-- @param user string containing the user name
	-- @return a new instance of Packet.PreAuth
	new = function(self, user, options, ver)
		local o = { auth_user = user, auth_options = options, version = ver }
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		local packet_type = 0x0376
		local UNKNOWN_MAP = {
			["Linuxi386/Linux-2.0.34-8.1.0"] = 	bin.pack("HCH","0238be0808", #self.auth_user, "00000001000000a851bfbf05000000504ebfbf7853bfbf"),
			["IBMPC/WIN_NT-8.1.0"]			 = 	bin.pack("HCH","0238be0808", #self.auth_user, "00000001000000a851bfbf05000000504ebfbf7853bfbf"),
			["IBMPC/WIN_NT64-9.1.0"] = bin.pack("H", "0201040000000100000001050000000101"),
			["x86_64/Linux 2.4.xx"] =  bin.pack("H", "0201040000000100000001050000000101"),
		}
		local unknown = UNKNOWN_MAP[self.version] or ""
		local data = bin.pack(">SSA", self.flags, packet_type, unknown)

		data = data .. bin.pack("CA", #self.auth_user, self.auth_user )
		for _, v in ipairs( Packet.PreAuth.param_order ) do
			for k, v2 in pairs(v) do
				data = data .. Marshaller.marshalKvp( k, self.auth_options[v2] )
			end
		end
		
		return data
	end,
	
	--- Parses the PreAuth packet response and extracts data needed to
	--  perform authentication
	--
	-- @param tns Packet.TNS containing the TNS packet recieved from the server
	-- @return table containing the keys and values returned by the server
	parseResponse = function( self, tns )
		local kvps = {}
		local pos, kvp_count = bin.unpack( "C", tns.data, 4 )
		pos = 6
		
		for kvp_itr=1, kvp_count do
			local key, val, kvp_flags
			pos, key, val, kvp_flags = Marshaller.unmarshalKvp( tns.data, pos )
			-- we don't actually do anything with the flags currently, but they're there
			kvps[key] = val
		end

		return true, kvps
	end,

}

-- Packet containing authentication data
Packet.Auth = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
	param_order = { 
		{ ['key'] = "AUTH_RTT", ['def'] = "25456" },
		{ ['key'] = "AUTH_CLNT_MEM", ['def'] = "4096" },
		{ ['key'] = "AUTH_TERMINAL", ['var'] = "auth_term" },
		{ ['key'] = "AUTH_PROGRAM_NM", ['var'] = "auth_prog" },
		{ ['key'] = "AUTH_MACHINE", ['var'] = "auth_machine" },
		{ ['key'] = "AUTH_PID", ['var'] = "auth_pid" },
		{ ['key'] = "AUTH_SID", ['var'] = "auth_sid" },
		{ ['key'] = "AUTH_ACL", ['def'] = "4400" },
		{ ['key'] = "AUTH_ALTER_SESSION", ['def'] = "ALTER SESSION SET TIME_ZONE='+02:00'\0" },
		{ ['key'] = "AUTH_LOGICAL_SESSION_ID", ['def'] = select(2, bin.unpack("H16", openssl.rand_pseudo_bytes(16))) },
		{ ['key'] = "AUTH_FAILOVER_ID", ['def'] = "" },
	},

	--- Creates a new Auth packet
	--
	-- @param auth_sesskey the encrypted session key
	-- @param auth_pass the encrypted user password
	-- @return a new instance of Packet.Auth
	new = function(self, user, options, auth_sesskey, auth_pass, ver)
		local o = {
			auth_sesskey = auth_sesskey,
			auth_pass = auth_pass,
			auth_options = options,
			user = user,
			version = ver
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		local UNKNOWN_MAP = {
			["Linuxi386/Linux-2.0.34-8.1.0"] = 	bin.pack("HCH","0338be0808", #self.user, "00000001010000cc7dbfbf0d000000747abfbf608abfbf"),
			["IBMPC/WIN_NT-8.1.0"] = 			bin.pack("HCH","0338be0808", #self.user, "00000001010000cc7dbfbf0d000000747abfbf608abfbf"),
			["IBMPC/WIN_NT64-9.1.0"] = 			bin.pack("H","03010400000001010000010d0000000101"),
			["x86_64/Linux 2.4.xx"]  = 			bin.pack("H","03010400000001010000010d0000000101")
		}
		
		local sess_id = select(2, bin.unpack("H16", openssl.rand_pseudo_bytes(16)))
		local unknown = UNKNOWN_MAP[self.version] or ""
		local data = bin.pack(">SSA", self.flags, 0x0373, unknown)
		data = data .. bin.pack("CA", #self.user, self.user )
		data = data .. Marshaller.marshalKvp( "AUTH_SESSKEY", self.auth_sesskey, 1 )
		data = data .. Marshaller.marshalKvp( "AUTH_PASSWORD", self.auth_pass )
								
		for k, v in ipairs( self.param_order ) do
			if ( v['def'] ) then
				data = data .. Marshaller.marshalKvp( v['key'], v['def'] )
			elseif ( self.auth_options[ v['var'] ] ) then
				data = data .. Marshaller.marshalKvp( v['key'], self.auth_options[ v['var'] ] )
			elseif ( self[ v['var'] ] ) then
				data = data .. Marshaller.marshalKvp( v['key'], self[ v['var'] ] )
			end
		end
		return data 
	end,
	
	-- Parses the response of an Auth packet
	--
	-- @param tns Packet.TNS containing the TNS packet recieved from the server
	-- @return table containing the key pair values from the Auth packet
	parseResponse = function( self, tns )
		local kvps = {}
		local pos, kvp_count = bin.unpack( "C", tns.data, 4 )
		pos = 6
		
		for kvp_itr=1, kvp_count do
			local key, val, kvp_flags
			pos, key, val, kvp_flags = Marshaller.unmarshalKvp( tns.data, pos )
			-- we don't actually do anything with the flags currently, but they're there
			kvps[key] = val
		end

		return true, kvps
	end,
	
}

Packet.SNS = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
	
	-- Creates a new SNS instance
	--
	-- @return o new instance of the SNS packet
	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	

	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		return  bin.pack("SH", self.flags, 
			[[ 
				deadbeef00920b1006000004000004000300000000000400050b10060000080
				001000015cb353abecb00120001deadbeef0003000000040004000100010002
				0001000300000000000400050b10060000020003e0e100020006fcff0002000
				200000000000400050b100600000c0001001106100c0f0a0b08020103000300
				0200000000000400050b10060000030001000301
			]] )
	end,	
}

-- Packet containing protocol negotiation
Packet.ProtoNeg = {

	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
	
	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		local pfx = bin.pack(">SH", self.flags, "0106050403020100")
		return pfx .. "Linuxi386/Linux-2.0.34-8.1.0\0"		
	end,		

	--- Parses and verifies the server response
	--
	-- @param tns Packet.TNS containing the response from the server
	parseResponse = function( self, tns )
		local pos, flags, neg, ver, _, srv = bin.unpack(">SCCCz", tns.data)
		if ( neg ~= 1 ) then
			return false, "Error protocol negotiation failed"
		end
		
		if ( ver ~= 6 ) then
			return false, ("Error protocol version (%d) not supported"):format(ver)
		end
		return true, srv
	end

}

Packet.Unknown1 = {

	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
	
	--- Creates a new Packet.Unknown1
	--
	-- @param version containing the version of the packet to send
	-- @return new instance of Packet.Unknown1
	new = function(self, os)
		local o = { os = os }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )

		if (  self.os:match("IBMPC/WIN_NT[64]*[-]%d%.%d%.%d") ) then
			return bin.pack(">SH", self.flags, [[
				02b200b2004225060101010d010105010101010101017fff0309030301007f0
				11fff010301013f01010500010702010000180001800000003c3c3c80000000
				d007000100010001000000020002000a00000008000800010000000c000c000
				a00000017001700010000001800180001000000190019001800190001000000
				1a001a0019001a00010000001b001b000a001b00010000001c001c0016001c0
				0010000001d001d0017001d00010000001e001e0017001e00010000001f001f
				0019001f0001000000200020000a00200001000000210021000a00210001000
				0000a000a00010000000b000b00010000002800280001000000290029000100
				000075007500010000007800780001000001220122000100000123012300010
				12300010000012401240001000001250125000100000126012600010000012a
				012a00010000012b012b00010000012c012c00010000012d012d00010000012
				e012e00010000012f012f000100000130013000010000013101310001000001
				320132000100000133013300010000013401340001000001350135000100000
				136013600010000013701370001000001380138000100000139013900010000
				013b013b00010000013c013c00010000013d013d00010000013e013e0001000
				0013f013f000100000140014000010000014101410001000001420142000100
				000143014300010000014701470001000001480148000100000149014900010
				000014b014b00010000014d014d00010000014e014e00010000014f014f0001
				000001500150000100000151015100010000015201520001000001530153000
				100000154015400010000015501550001000001560156000100000157015700
				0101570001000001580158000100000159015900010000015a015a000100000
				15c015c00010000015d015d0001000001620162000100000163016300010000
				0167016700010000016b016b00010000017c017c0001014200010000017d017
				d00010000017e017e00010000017f017f000100000180018000010000018101
				810001000001820182000100000183018300010000018401840001000001850
				18500010000018601860001000001870187000100000189018900010000018a
				018a00010000018b018b00010000018c018c00010000018d018d00010000018
				e018e00010000018f018f000100000190019000010000019101910001000001
				940194000101250001000001950195000100000196019600010000019701970
				0010000019d019d00010000019e019e00010000019f019f0001000001a001a0
				0001000001a101a10001000001a201a20001000001a301a30001000001a401a
				40001000001a501a50001000001a601a60001000001a701a70001000001a801
				a80001000001a901a90001000001aa01aa0001000001ab01ab0001000001ad0
				1ad0001000001ae01ae0001000001af01af0001000001b001b00001000001b1
				01b10001000001c101c10001000001c201c2000101250001000001c601c6000
				1000001c701c70001000001c801c80001000001c901c90001000001ca01ca00
				01019f0001000001cb01cb000101a00001000001cc01cc000101a2000100000
				1cd01cd000101a30001000001ce01ce000101b10001000001cf01cf00010122
				0001000001d201d20001000001d301d3000101ab0001000001d401d40001000
				001d501d50001000001d601d60001000001d701d70001000001d801d8000100
				0001d901d90001000001da01da0001000001db01db0001000001dc01dc00010
				00001dd01dd0001000001de01de0001000001df01df0001000001e001e00001
				000001e101e10001000001e201e20001000001e301e30001016b0001000001e
				401e40001000001e501e50001000001e601e60001000001ea01ea0001000001
				eb01eb0001000001ec01ec0001000001ed01ed0001000001ee01ee000100000
				1ef01ef0001000001f001f00001000001f201f20001000001f301f300010000
				01f401f40001000001f501f50001000001f601f60001000001fd01fd0001000
				001fe01fe000100000201020100010000020202020001000002040204000100
				000205020500010000020602060001000002070207000100000208020800010
				0000209020900010000020a020a00010000020b020b00010000020c020c0001
				0000020d020d00010000020e020e00010000020f020f0001000002100210000
				100000211021100010000021202120001000002130213000100000214021400
				010000021502150001000002160216000100000217021700010000021802180
				00100000219021900010000021a021a00010000021b021b00010000021c021c
				00010000021d021d00010000021e021e00010000021f021f000100000220022
				000010000022102210001000002220222000100000223022300010000022402
				240001000002250225000100000226022600010000022702270001000002280
				228000100000229022900010000022a022a00010000022b022b00010000022c
				022c00010000022d022d00010000022e022e00010000022f022f00010000023
				102310001000002320232000100000233023300010000023402340001000002
				3702370001000002380238000100000239023900010000023a023a000100000
				23b023b00010000023c023c00010000023d023d00010000023e023e00010000
				023f023f0001000002400240000100000241024100010000024202420001000
				002430243000100000244024400010000
				]])
		elseif ( "x86_64/Linux 2.4.xx" == self.os ) then
			return bin.pack(">SH", self.flags, [[
				02b200b2004221060101010d01010401010101010101ffff0308030001003f0
				1073f010101010301050201000018800000003c3c3c80000000d00700010001
				0001000000020002000a00000008000800010000000c000c000a00000017001
				7000100000018001800010000001900190018001900010000001a001a001900
				1a00010000001b001b000a001b00010000001c001c0016001c00010000001d0
				01d0017001d00010000001e001e0017001e00010000001f001f0019001f0001
				000000200020000a00200001000000210021000a002100010000000a000a000
				10000000b000b00010000002800280001000000290029000100000075007500
				010000007800780001000001220122000100000123012300010123000100000
				12401240001000001250125000100000126012600010000012a012a00010000
				012b012b00010000012c012c00010000012d012d00010000012e012e0001000
				0012f012f000100000130013000010000013101310001000001320132000100
				000133013300010000013401340001000001350135000100000136013600010
				000013701370001000001380138000100000139013900010000013b013b0001
				0000013c013c00010000013d013d00010000013e013e00010000013f013f000
				100000140014000010000014101410001000001420142000100000143014300
				010000014701470001000001480148000100000149014900010000014b014b0
				0010000014d014d00010000014e014e00010000014f014f0001000001500150
				000100000151015100010000015201520001000001530153000100000154015
				400010000015501550001000001560156000100000157015700010157000100
				0001580158000100000159015900010000015a015a00010000015c015c00010
				000015d015d0001000001620162000100000163016300010000016701670001
				0000016b016b00010000017c017c0001014200010000017d017d00010000017
				e017e00010000017f017f000100000180018000010000018101810001000001
				820182000100000183018300010000018401840001000001850185000100000
				18601860001000001870187000100000189018900010000018a018a00010000
				018b018b00010000018c018c00010000018d018d00010000018e018e0001000
				0018f018f000100000190019000010000019101910001000001940194000101
				2500010000019501950001000001960196000100000197019700010000019d0
				19d00010000019e019e00010000019f019f0001000001a001a00001000001a1
				01a10001000001a201a20001000001a301a30001000001a401a40001000001a
				501a50001000001a601a60001000001a701a70001000001a801a80001000001
				a901a90001000001aa01aa0001000001ab01ab0001000001ad01ad000100000
				1ae01ae0001000001af01af0001000001b001b00001000001b101b100010000
				01c101c10001000001c201c2000101250001000001c601c60001000001c701c
				70001000001c801c80001000001c901c90001000001ca01ca0001019f000100
				0001cb01cb000101a00001000001cc01cc000101a20001000001cd01cd00010
				1a30001000001ce01ce000101b10001000001cf01cf000101220001000001d2
				01d20001000001d301d3000101ab0001000001d401d40001000001d501d5000
				1000001d601d60001000001d701d70001000001d801d80001000001d901d900
				01000001da01da0001000001db01db0001000001dc01dc0001000001dd01dd0
				001000001de01de0001000001df01df0001000001e001e00001000001e101e1
				0001000001e201e20001000001e301e30001016b0001000001e401e40001000
				001e501e50001000001e601e60001000001ea01ea0001000001eb01eb000100
				0001ec01ec0001000001ed01ed0001000001ee01ee0001000001ef01ef00010
				00001f001f00001000001f201f20001000001f301f30001000001f401f40001
				000001f501f50001000001f601f60001000001fd01fd0001000001fe01fe000
				100000201020100010000020202020001000002040204000100000205020500
				010000020602060001000002070207000100000208020800010000020902090
				0010000020a020a00010000020b020b00010000020c020c00010000020d020d
				00010000020e020e00010000020f020f0001000002100210000100000211021
				100010000021202120001000002130213000100000214021400010000021502
				150001000002160216000100000217021700010000021802180001000002190
				21900010000021a021a00010000021b021b0001000000030002000a00000004
				0002000a0000000500010001000000060002000a000000070002000a0000000
				9000100010000000d0000000e0000000f001700010000001000000011000000
				12000000130000001400000015000000160000002700780001015d000101260
				0010000003a003a0001000000440002000a00000045000000460000004a006d
				00010000004c0000005b0002000a0000005e000100010000005f00170001000
				000600060000100000061006000010000006400640001000000650065000100
				0000660066000100000068000000690000006a006a00010000006c006d00010
				000006d006d00010000006e006f00010000006f006f00010000007000700001
				000000710071000100000072007200010000007300730001000000740066000
				100000076000000770000007900790001
			]])
		else
			return bin.pack(">SH", self.flags, "02b200b2004225060101010d010105010101010101017fff0309030301007f011" ..
				"fff010301013f01010500010702010000180001800000003c3c3c80000000d007")
		end
	end,		
	
}


--- This packet is only used by Oracle10 and older
Packet.Unknown2 = {

	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
	
	new = function(self, os)
		local o = { os = os }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		if ( "x86_64/Linux 2.4.xx" == self.os ) then
			return bin.pack(">SH", self.flags, [[
				0000007a007a00010000007b007b00010000008800000092009200010000009
				300930001000000980002000a000000990002000a0000009a0002000a000000
				9b000100010000009c000c000a000000ac0002000a000000b200b2000100000
				0b300b30001000000b400b40001000000b500b50001000000b600b600010000
				00b700b70001000000b8000c000a000000b900b20001000000ba00b30001000
				000bb00b40001000000bc00b50001000000bd00b60001000000be00b7000100
				0000bf000000c0000000c300700001000000c400710001000000c5007200010
				00000d000d00001000000d1000000e700e70001000000e800e70001000000e9
				00e90001000000f1006d0001000002030203000100000000]]
				)
		else
			return bin.pack(">SH", self.flags, [[
				024502450001000002460246000100000247024700010000024802480001000
				0024902490001000000030002000a000000040002000a000000050001000100
				0000060002000a000000070002000a00000009000100010000000d0000000e0
				000000f00170001000000100000001100000012000000130000001400000015
				000000160000002700780001015d0001012600010000003a003a00010000004
				40002000a00000045000000460000004a006d00010000004c0000005b000200
				0a0000005e000100010000005f0017000100000060006000010000006100600
				001000000640064000100000065006500010000006600660001000000680000
				00690000006a006a00010000006c006d00010000006d006d00010000006e006
				f00010000006f006f0001000000700070000100000071007100010000007200
				720001000000730073000100000074006600010000007600000077000000790
				07900010000007a007a00010000007b007b0001000000880000009200920001
				0000009300930001000000980002000a000000990002000a0000009a0002000
				a0000009b000100010000009c000c000a000000ac0002000a000000b200b200
				01000000b300b30001000000b400b40001000000b500b50001000000b600b60
				001000000b700b70001000000b8000c000a000000b900b20001000000ba00b3
				0001000000bb00b40001000000bc00b50001000000bd00b60001000000be00b
				70001000000bf000000c0000000c300700001000000c400710001000000c500
				720001000000d000d00001000000d1000000e700e70001000000e800e700010
				00000e900e90001000000f1006d0001000002030203000100000000
				]])
		end
	end,		
	
}

-- Signals that we're about to close the connection
Packet.EOF = {

	tns_type = Packet.TNS.Type.DATA,
	flags = 0x0040,
	
	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		return bin.pack(">S", self.flags )
	end	
}

Packet.PostLogin = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0x0000,
	
	-- Creates a new PostLogin instance
	--
	-- @param sessid number containing session id
	-- @return o a new instance of PostLogin
	new = function(self, sessid)
		local o = { sessid = sessid }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		local unknown1 = "116b04"
		local unknown2 = "0000002200000001000000033b05fefffffff4010000fefffffffeffffff"
		return bin.pack(">SHCH", self.flags, unknown1, tonumber(self.sessid), unknown2 )
	end
	
}

-- Class responsible for sending queries to the server and handling the first
-- row returned by the server. This class is 100% based on packet captures and
-- guesswork.
Packet.Query = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0x0000,
	
	--- Creates a new instance of Query
	-- @param query string containing the SQL query
	-- @return instance of Query
	new = function(self, query)
		local o = { query = query, counter = 0 }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Gets the current counter value
	-- @return counter number containing the current counter value
	getCounter = function(self) return self.counter end,
	
	--- Sets the current counter value
	-- This function is called from sendTNSPacket
	-- @param counter number containing the counter value to set
	setCounter = function(self, counter) self.counter = counter end,
		
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	__tostring = function( self )
		local unknown1 = "035e"
		local unknown2 = "6180000000000000feffffff"
		local unknown3 = "000000feffffff0d000000fefffffffeffffff000000000100000000000000000000000000000000000000feffffff00000000fefffffffeffffff54d25d020000000000000000fefffffffeffffff0000000000000000000000000000000000000000"
		local unknown4 = "01000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000"
		return bin.pack(">SHCHCHCAH", self.flags, unknown1, self.counter, unknown2, #self.query, unknown3, #self.query, self.query, unknown4 )
	end,
	
	--- Parses the Query response from the server
	-- @param tns response as received from the <code>Comm.recvTNSPacket</code>
	--        function.
	-- @return result table containing:
	--  <code>columns</code> - a column indexed table with the column names
	--  <code>types</code>   - a column indexed table with the data types
	--  <code>rows</code>    - a table containing a row table for each row
	--                         the row table is a column indexed table of
	--                         column values.
	parseResponse = function( self, tns )
		local data = tns.data
		local result = {}
		
		local pos, columns = bin.unpack("C", tns.data, 35)
		
		pos = 40
		for i=1, columns do
			local sql_type
			pos, sql_type = bin.unpack("C", data, pos)
			pos = pos + 34
			local name, len
			pos, len = bin.unpack("C", tns.data, pos)
			pos, name= bin.unpack("A" .. len, tns.data, pos)
			result.columns = result.columns or {}
			result.types = result.types or {}
			table.insert(result.columns, name)
			table.insert(result.types, sql_type)
			pos = pos + 10
		end
		
		pos = pos + 55
		
		result.rows = {}
		local row = {}
		for i=1, columns do
			local val, len
			pos, len = bin.unpack("C", tns.data, pos)
			pos, val = bin.unpack("A" .. len, tns.data, pos)

			-- if we're at the first row and first column and the len is 0
			-- assume we got an empty resultset
			if ( len == 0 and #result.rows == 0 and i == 1 ) then
				return true, { data = result, moredata = false }
			end

			local sql_type = result.types[i]
			if ( DataTypeDecoders[sql_type] ) then
				val = DataTypeDecoders[sql_type](val)
			end
			table.insert(row, val)
		end
		table.insert(result.rows, row)
		
		local moredata = true
		-- check if we've got any more data?
		if ( #data > pos + 97 ) then
			local len, err
			pos, len = bin.unpack(">S", data, pos + 97)
			pos, err = bin.unpack("A" .. len, data, pos)
			if ( err:match("^ORA%-01403") ) then
				moredata = false
			end
		end
		
		return true, { data = result, moredata = moredata }
	end,
}

-- Class responsible for acknowledging a query response from the server
-- and handles the next several rows returned by the server. This class
-- is mostly based on packet captures and guesswork.
Packet.QueryResponseAck = {

	tns_type = Packet.TNS.Type.DATA,
	flags = 0x0000,
	
	--- Creates a new QueryResponseAck instance
	-- @param result table containing the results as received from the
	--        <code>Query.parseResponse</code> function.
	-- @return instance new instance of QueryResponseAck
	new = function(self, result)
		local o = { result = result }
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	--- Gets the current counter value
	-- @return counter number containing the current counter value
	getCounter = function(self) return self.counter end,
	
	--- Sets the current counter value
	-- This function is called from sendTNSPacket
	-- @param counter number containing the counter value to set
	setCounter = function(self, counter) self.counter = counter end,
	
	--- Serializes the packet into a string suitable to be sent to the DB
	-- server.
	-- @return str string containing the serialized packet
	__tostring = function(self)
		return bin.pack(">SHCH", self.flags, "0305", self.counter, "030000000f000000")
	end,
	
	--
	-- This is how I (Patrik Karlsson) think this is supposed to work
	-- At this point we have the 2nd row (the query response has the first)
	-- Every row looks like this, where the leading mask marker (0x15) and mask
	-- is optional.
	-- | (mask mark)| (bytes) | sor  | byte | len * bytes | ... next_column |
	-- |  0x15      | [mask]  | 0x07 | [len]| [column_val]| ... next_column |

	-- The mask is used in order to achieve "compression" and is essentially
	-- at a bit mask that decides what columns should be fetched from the
	-- preceeding row. The mask is provided in reverse order and a set bit
	-- indicates that data is provided while an unset bit indicates that the
	-- column data should be fetched from the previous row.
	--
	-- Once a value is fetched the sql data type is verified against the
	-- DataTypeDecoder table. If there's a function registered for the fetched
	-- data it is run through a decoder, that decodes the *real* value from
	-- the encoded data.
	--
	parseResponse = function( self, tns )		
		local data = tns.data
		local pos, len = bin.unpack("C", data, 21)
		local mask = ""

		-- calculate the initial mask
		if ( len > 0 ) then
			while( len > 0) do
				local mask_part
				pos, mask_part = bin.unpack("B", data, pos)
				mask = mask .. mask_part:reverse()
				len = len - 1
			end
			pos = pos + 4
		else
			pos = pos +3 
		end

		while(true) do
			local row = {}
			local result = self.result
			local cols = #result.columns

			-- check for start of data marker
			local marker
			pos, marker = bin.unpack("C", data, pos)
			if ( marker == 0x15 ) then
				mask = ""
				local _
				-- not sure what this value is
				pos, _ = bin.unpack("<S", data, pos)

				-- calculate the bitmask for the columns that do contain
				-- data.
				len = cols
				while( len > 0 ) do
					local mask_part
					pos, mask_part = bin.unpack("B", data, pos)
					mask = mask .. mask_part:reverse()
					len = len - 8
				end
				pos, marker = bin.unpack("C", data, pos)
			end
			if ( marker ~= 0x07 ) then
				stdnse.print_debug(2, "Encountered unknown marker: %d", marker)
				break
			end

			local val
			local rows = self.result.rows
			for col=1, cols do
				if ( #mask > 0 and mask:sub(col, col) == '0' ) then
					val = rows[#rows][col]
				else
					pos, len = bin.unpack("C", data, pos)
					pos, val = bin.unpack("A" .. len, data, pos)
				
					local sql_type = result.types[col]
					if ( DataTypeDecoders[sql_type] ) then
						val = DataTypeDecoders[sql_type](val)
					end
				end
				table.insert(row, val)
			end

			-- add row to result
			table.insert(rows, row)
		end

		return true, tns.data
	end,
	
}

Marshaller = {
	--- Marshals a TNS key-value pair data structure
	--
	-- @param key The key
	-- @param value The value
	-- @param flags The flags
	-- @return A binary packed string representing the KVP structure
	marshalKvp = function( key, value, flags )
		return Marshaller.marshalKvpComponent( key ) .. 
			Marshaller.marshalKvpComponent( value ) ..
			bin.pack( "<I", ( flags or 0 ) )
	end,
	
	--- Parses a TNS key-value pair data structure.
	--
	-- @param data Packed string to parse
	-- @param pos Position in the string at which the KVP begins
	-- @return table containing the last position read, the key, the value, and the KVP flags
	unmarshalKvp = function( data, pos )
		local key, value, flags
		
		pos, key   = Marshaller.unmarshalKvpComponent( data, pos )
		pos, value = Marshaller.unmarshalKvpComponent( data, pos )
		pos, flags = bin.unpack("<I", data, pos )
		
		return pos, key, value, flags
	end,
	
	--- Marshals a key or value element from a TNS key-value pair data structure
	--
	-- @param value The key or value
	-- @return A binary packed string representing the element
	marshalKvpComponent = function( value )
		local result = ""
		value = value or ""

		result = result .. bin.pack( "<I", #value )
		if ( #value > 0 ) then
			-- 64 bytes seems to be the maximum length before Oracle starts
			-- chunking strings
			local MAX_CHUNK_LENGTH = 64
			local split_into_chunks = ( #value > MAX_CHUNK_LENGTH )

			if ( not( split_into_chunks ) ) then
				-- It's pretty easy if we don't have to split up the string
				result = result .. bin.pack( "p", value )
			else
				-- Otherwise, it's a bit more involved:
				-- First, write the multiple-chunk indicator
				result = result .. bin.pack( "C", 0xFE )

				-- Loop through the string, chunk by chunk
				while ( #value > 0 ) do
					-- Figure out how much we're writing in this chunk, the
					-- remainder of the string, or the maximum, whichever is less
					local write_length = MAX_CHUNK_LENGTH
					if (#value < MAX_CHUNK_LENGTH) then
						write_length = #value
					end

					-- get a substring of what we're going to write...
					local write_value = value:sub( 1, write_length )
					-- ...and remove that piece from the remaining string
					value = value:sub( write_length + 1 )
					result = result .. bin.pack( "p", write_value )
				end

				-- put a null byte at the end
				result = result .. bin.pack( "C", 0 )
			end
		end

		return result
	end,
	
	--- Parses a key or value element from a TNS key-value pair data structure.
	--
	-- @param data Packed string to parse
	-- @param pos Position in the string at which the element begins
	-- @return table containing the last position read and the value parsed
	unmarshalKvpComponent = function( data, pos )
		local value_len, chunk_len
		local value, chunk = "", ""
		local has_multiple_chunks = false

		-- read the 32-bit total length of the value
		pos, value_len = bin.unpack("<I", data, pos )
		if ( value_len == 0 ) then
			value = ""
		else
			-- Look at the first byte after the total length. If the value is
			-- broken up into multiple chunks, this will be indicated by this
			-- byte being 0xFE.
			local _, first_byte = bin.unpack("C", data, pos )
			if ( first_byte == 0xFE ) then
				has_multiple_chunks = true
				pos = pos + 1 -- move pos past the multiple-chunks indicator
			end

			-- Loop through the chunks until we read the whole value
			while ( value:len() < value_len ) do
				pos, chunk = bin.unpack("p", data, pos )
				value = value .. chunk
			end

			if ( has_multiple_chunks ) then
				pos = pos + 1 -- there's a null byte after the last chunk
			end
		end

		return pos, value
	end,
}


-- The TNS communication class uses the TNSSocket to transmit data
Comm = {
	
	--- Creates a new instance of the Comm class
	--
	-- @param socket containing a TNSSocket
	-- @return new instance of Comm
	new = function(self, socket)
		local o = { 
			socket = socket, 
			data_counter = 06
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,

	--- Attemts to send a TNS packet over the socket
	--
	-- @param pkt containing an instance of a Packet.*
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	sendTNSPacket = function( self, pkt )
		local tns = Packet.TNS:new( pkt.tns_type )
		if ( pkt.setCounter ) then
			pkt:setCounter(self.data_counter)
			self.data_counter = self.data_counter + 1
		end
		tns.data = tostring(pkt)
		tns.length = #tns.data + 8

		-- buffer incase of RESEND
		self.pkt = pkt

		return self.socket:send( tostring(tns) )
	end,

	--- Handles communication when a MARKER packet is recieved and retrieves
	--  the following error message
	--
	-- @return false always to indicate that an error occured
	-- @return msg containing the error message
	handleMarker = function( self )
		local status, tns = self:recvTNSPacket()

		if ( not(status) or tns.type ~= Packet.TNS.Type.MARKER ) then
			return false, "ERROR: failed to handle marker sent by server"
		end

		-- send our marker
		status = self:sendTNSPacket( Packet.Attention:new( 1, bin.pack("H", "0002") ) )
		if ( not(status) ) then
			return false, "ERROR: failed to send marker to server"
		end

		status, tns = self:recvTNSPacket()
		if ( not(status) or tns.type ~= Packet.TNS.Type.DATA ) then
			return false, "ERROR: expecting DATA packet"
		end

		-- check if byte 12 is set or not, this should help us distinguish the offset
		-- to the error message in Oracle 10g and 11g
		local pos, b1 = bin.unpack("C", tns.data, 10)
		pos = (b1 == 1) and 99 or 69

		-- fetch the oracle error and return it
		local msg
		pos, msg = bin.unpack("p", tns.data, pos )

		return false, msg		
	end,
	
	--- Recieves a TNS packet and handles TNS-resends
	--
	-- @return status true on success, false on failure
	-- @return tns Packet.TNS containing the recieved packet or err on failure
	recvTNSPacket = function( self )
		local tns
		local retries = 5

		repeat
			local function recv()
				local status, header = self.socket:receive_buf( match.numbytes(8), true )
				if ( not(status) ) then return status, header end

				local _, length = bin.unpack(">S", header )
				local status, data = self.socket:receive_buf( match.numbytes(length - 8), true )
				if ( not(status) ) then
					return false, data
				else
					return status, Packet.TNS.parse(header .. data)
				end
			end

			local status
			status, tns = recv()
			if ( not(status) ) then
				if ( retries == 0 ) then
					return false, "ERROR: recvTNSPacket failed to receive TNS headers"
				end
				retries = retries - 1
			elseif ( tns.type == Packet.TNS.Type.RESEND ) then
				self:sendTNSPacket( self.pkt )
			end
		until ( status and tns.type ~= Packet.TNS.Type.RESEND )

		return true, tns
	end,
	
	--- Sends a TNS packet and recieves (and handles) the response
	--
	-- @param pkt containingt the Packet.* to send to the server
	-- @return status true on success, false on failure
	-- @return the parsed response as return from the respective parseResponse
	--         function or error message if status was false
	exchTNSPacket = function( self, pkt )
		local status = self:sendTNSPacket( pkt )
		local tns, response
		
		if ( not(status) ) then
			return false, "sendTNSPacket failed"
		end

		status, tns = self:recvTNSPacket()
		if ( not(status) ) then
			return false, tns
		end

		--- handle TNS MARKERS
		if ( tns.type == Packet.TNS.Type.MARKER ) then
			return self:handleMarker()
		end

		if ( pkt.parseResponse ) then
			status, response = pkt:parseResponse( tns )
		end

		return status, response
	end
	
}

--- Class that handles all Oracle encryption
Crypt = {

	-- Test function, not currently in use
	Decrypt11g = function(self, c_sesskey, s_sesskey, auth_password, pass, salt )
		local combined_sesskey = ""
		local sha1 = openssl.sha1(pass .. salt) .. "\0\0\0\0"
		local auth_sesskey = s_sesskey
		local auth_sesskey_c = c_sesskey 
		local server_sesskey = openssl.decrypt( "aes-192-cbc", sha1, nil, auth_sesskey )
		local client_sesskey = openssl.decrypt( "aes-192-cbc", sha1, nil, auth_sesskey_c )

		combined_sesskey = ""
		for i=17, 40 do
			combined_sesskey = combined_sesskey .. string.char( bit.bxor( string.byte(server_sesskey, i), string.byte(client_sesskey,i) ) )
		end
		combined_sesskey = ( openssl.md5( combined_sesskey:sub(1,16) ) .. openssl.md5( combined_sesskey:sub(17) ) ):sub(1, 24)

		local p = openssl.decrypt( "aes-192-cbc", combined_sesskey, nil, auth_password, false )
		return p:sub(17)
	end,

	--- Creates an Oracle 10G password hash
	--
	-- @param username containing the Oracle user name
	-- @param password containing the Oracle user password
	-- @return hash containing the Oracle hash
	HashPassword10g = function( self, username, password )
		local uspw = ( username .. password ):gsub("(%w)", "\0%1")
		local key = bin.pack("H", "0123456789abcdef")

		-- do padding
		if ( #uspw % 8 > 0 ) then
			for i=1,(8-(#uspw % 8)) do
				uspw = uspw .. "\0"
			end
		end

		local iv2 = openssl.encrypt( "DES-CBC", key, nil, uspw, false ):sub(-8)
		local enc = openssl.encrypt( "DES-CBC", iv2, nil, uspw, false ):sub(-8)
		return enc
	end,

	-- Test function, not currently in use
	Decrypt10g = function(self, user, pass, srv_sesskey_enc )
		local pwhash = self:HashPassword10g( user:upper(), pass:upper() ) .. "\0\0\0\0\0\0\0\0"
		local cli_sesskey_enc = bin.pack("H", "7B244D7A1DB5ABE553FB9B7325110024911FCBE95EF99E7965A754BC41CF31C0")
		local srv_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, srv_sesskey_enc )
		local cli_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, cli_sesskey_enc )
		local auth_pass = bin.pack("H", "4C5E28E66B6382117F9D41B08957A3B9E363B42760C33B44CA5D53EA90204ABE" )
		local combined_sesskey = ""
		local pass 

		for i=17, 32 do
			combined_sesskey = combined_sesskey .. string.char( bit.bxor( string.byte(srv_sesskey, i), string.byte(cli_sesskey, i) ) )
		end
		combined_sesskey = openssl.md5( combined_sesskey )

		pass = openssl.decrypt( "AES-128-CBC", combined_sesskey, nil, auth_pass ):sub(17)

		print( select(2, bin.unpack("H" .. #srv_sesskey, srv_sesskey )))
		print( select(2, bin.unpack("H" .. #cli_sesskey, cli_sesskey )))
		print( select(2, bin.unpack("H" .. #combined_sesskey, combined_sesskey )))
		print( "pass=" .. pass )
	end,
	
	--- Performs the relevant encryption needed for the Oracle 10g response
	--
	-- @param user containing the Oracle user name
	-- @param pass containing the Oracle user password
	-- @param srv_sesskey_enc containing the encrypted server session key as
	--        recieved from the PreAuth packet
	-- @return cli_sesskey_enc the encrypted client session key
	-- @return auth_pass the encrypted Oracle password
	Encrypt10g = function( self, user, pass, srv_sesskey_enc )

		local pwhash = self:HashPassword10g( user:upper(), pass:upper() ) .. "\0\0\0\0\0\0\0\0"
		-- We're currently using a static client session key, this should
		-- probably be changed to a random value in the future
		local cli_sesskey = bin.pack("H", "FAF5034314546426F329B1DAB1CDC5B8FF94349E0875623160350B0E13A0DA36")
		local srv_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, srv_sesskey_enc )
		local cli_sesskey_enc = openssl.encrypt( "AES-128-CBC", pwhash, nil, cli_sesskey )
		-- This value should really be random, not this static cruft
		local rnd = bin.pack("H", "4C31AFE05F3B012C0AE9AB0CDFF0C508")
		local combined_sesskey = ""
		local auth_pass
		
		for i=17, 32 do
			combined_sesskey = combined_sesskey .. string.char( bit.bxor( string.byte(srv_sesskey, i), string.byte(cli_sesskey, i) ) )
		end
		combined_sesskey = openssl.md5( combined_sesskey )
		auth_pass = openssl.encrypt("AES-128-CBC", combined_sesskey, nil, rnd .. pass, true )
		auth_pass = select(2, bin.unpack("H" .. #auth_pass, auth_pass))
		cli_sesskey_enc = select(2, bin.unpack("H" .. #cli_sesskey_enc, cli_sesskey_enc))
		return cli_sesskey_enc, auth_pass
	end,

	--- Performs the relevant encryption needed for the Oracle 11g response
	--
	-- @param pass containing the Oracle user password
	-- @param srv_sesskey_enc containing the encrypted server session key as
	--        recieved from the PreAuth packet
	-- @param auth_vrfy_data containing the password salt as recieved from the
	--        PreAuth packet
	-- @return cli_sesskey_enc the encrypted client session key
	-- @return auth_pass the encrypted Oracle password	
	Encrypt11g = function( self, pass, srv_sesskey_enc, auth_vrfy_data )

		-- This value should really be random, not this static cruft
		local rnd = openssl.rand_pseudo_bytes(16)
		local cli_sesskey = openssl.rand_pseudo_bytes(40) .. bin.pack("H", "0808080808080808")
		local pw_hash = openssl.sha1(pass .. auth_vrfy_data) .. "\0\0\0\0"
		local srv_sesskey = openssl.decrypt( "aes-192-cbc", pw_hash, nil, srv_sesskey_enc )
		local auth_password
		local cli_sesskey_enc
		local combined_sesskey = ""
		local data = ""
		
		for i=17, 40 do
			combined_sesskey = combined_sesskey .. string.char( bit.bxor( string.byte(srv_sesskey, i), string.byte(cli_sesskey, i) ) )
		end
		combined_sesskey = ( openssl.md5( combined_sesskey:sub(1,16) ) .. openssl.md5( combined_sesskey:sub(17) ) ):sub(1, 24)

		cli_sesskey_enc = openssl.encrypt( "aes-192-cbc", pw_hash, nil, cli_sesskey )
		cli_sesskey_enc = select(2,bin.unpack("H" .. #cli_sesskey_enc, cli_sesskey_enc))

		auth_password = openssl.encrypt( "aes-192-cbc", combined_sesskey, nil, rnd .. pass, true )
		auth_password = select(2, bin.unpack("H" .. #auth_password, auth_password))

		return cli_sesskey_enc, auth_password
	end,
	
}

Helper = {
	
	--- Creates a new Helper instance
	--
	-- @param host table containing the host table as received by action
	-- @param port table containing the port table as received by action
	-- @param instance string containing the instance name
	-- @return o new instance of Helper			
	new = function(self, host, port, instance )
		local o = { 
			host = host,
			port = port,
			socket = nmap.new_socket(),
			dbinstance = instance or stdnse.get_script_args('tns.sid') or "orcl"
		}
		o.socket:set_timeout(30000)
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	--- Connects and performs protocol negotiation with the Oracle server
	--
	-- @return true on success, false on failure
	-- @return err containing error message when status is false
	Connect = function( self )
		local SUPPORTED_VERSIONS = {
			"IBMPC/WIN_NT64-9.1.0",
			"IBMPC/WIN_NT-8.1.0",
			"Linuxi386/Linux-2.0.34-8.1.0",
			"x86_64/Linux 2.4.xx"
		}
		local status, data = self.socket:connect( self.host.ip, self.port.number, "tcp" )
		local conn, packet, tns

		if( not(status) ) then return status, data	end
		
		self.comm = Comm:new( self.socket )

		status, self.version = self.comm:exchTNSPacket( Packet.Connect:new( self.host.ip, self.port.number, self.dbinstance ) )
		if ( not(status) ) then	return false, self.version end

		if ( self.version ~= ORACLE_VERSION_11G and self.version ~= ORACLE_VERSION_10G ) then
			return false, ("Unsupported Oracle Version (%d)"):format(self.version)
		end

		status = self.comm:exchTNSPacket( Packet.SNS:new( self.version ) )
		if ( not(status) ) then	return false, "ERROR: Helper.Connect failed" end

		status, self.os = self.comm:exchTNSPacket( Packet.ProtoNeg:new( self.version ) )
		if ( not(status) ) then
			return false, data
		end

		-- used for testing unsupported versions
		self.os = stdnse.get_script_args("tns.forceos") or self.os

		status = false
		for _, ver in pairs(SUPPORTED_VERSIONS) do
			if ( self.os == ver ) then
				status = true
				break
			end
		end

		if ( not(status) ) then
			stdnse.print_debug(2, "ERROR: Version %s is not yet supported", self.os)
			return false, ("ERROR: Connect to version %s is not yet supported"):format(self.os)
		end

		if ( self.os:match("IBMPC/WIN_NT") ) then
			status = self.comm:sendTNSPacket( Packet.Unknown1:new( self.os ) )
			if ( not(status) ) then
				return false, "ERROR: Helper.Connect failed"
			end			
			status, data = self.comm:sendTNSPacket( Packet.Unknown2:new( self.os ) )
			if ( not(status) ) then	return false, data end			

			status, data = self.comm:recvTNSPacket( Packet.Unknown2:new( ) )
			if ( not(status) ) then return false, data end			
			-- Oracle 10g under Windows needs this additional read, there's
			-- probably a better way to detect this by analysing the packets
			-- further.
			if ( self.version == ORACLE_VERSION_10G ) then
				status, data = self.comm:recvTNSPacket( Packet.Unknown2:new( ) )
				if ( not(status) ) then	return false, data end
			end
		elseif ( "x86_64/Linux 2.4.xx" == self.os ) then
			status = self.comm:sendTNSPacket( Packet.Unknown1:new( self.os ) )
			if ( not(status) ) then
				return false, "ERROR: Helper.Connect failed"
			end

			status = self.comm:sendTNSPacket( Packet.Unknown2:new( self.os ) )
			if ( not(status) ) then
				return false, "ERROR: Helper.Connect failed"
			end

			status, data = self.comm:recvTNSPacket( Packet.Unknown2:new( ) )
			if ( not(status) ) then
				return false, data
			end			

		else
			status = self.comm:exchTNSPacket( Packet.Unknown1:new( self.os ) )
			if ( not(status) ) then
				return false, "ERROR: Helper.Connect failed"
			end
		end
		
		return true
	end,
	
	--- Sends a command to the TNS lsnr
	-- It currently accepts and tries to send all commands recieved
	--
	-- @param cmd string containing the command to send to the server
	-- @return data string containing the result recieved from the server
	lsnrCtl = function( self, cmd )
		local status, data = self.socket:connect( self.host.ip, self.port.number, "tcp" )
		local conn, packet, tns, pkt

		if( not(status) ) then
			return status, data
		end

		self.comm = Comm:new( self.socket )
		pkt = Packet.Connect:new( self.host.ip, self.port.number, self.dbinstance )
		pkt:setCmd(cmd)

		if ( not(self.comm:exchTNSPacket( pkt )) ) then
			return false, self.version
		end

		data = ""
		repeat
			status, tns = self.comm:recvTNSPacket()
			if ( not(status) ) then
				self:Close()
				return status, tns
			end
			local _, flags = bin.unpack(">S", tns.data )
			data = data .. tns.data:sub(3)
		until ( flags ~= 0 )
		self:Close()

		return true, data
	end,
	
	--- Authenticates to the database
	--
	-- @param user containing the Oracle user name
	-- @param pass containing the Oracle user password
	-- @return true on success, false on failure
	-- @return err containing error message when status is false
	Login = function( self, user, password )
		local data, packet, status, tns, parser
		local sesskey_enc, auth_pass, auth
		local auth_options = AuthOptions:new()

		status, auth = self.comm:exchTNSPacket( Packet.PreAuth:new( user, auth_options, self.os ) )
		if ( not(status) ) then
			return false, auth
		end

		-- Check what version of the DB to authenticate against AND verify whether
		-- case sensitive login is enabled or not. In case-sensitive mode the salt
		-- is longer, so we check the length of auth["AUTH_VFR_DATA"]
		if ( self.version == ORACLE_VERSION_11G and #auth["AUTH_VFR_DATA"] > 2 ) then
			sesskey_enc, auth_pass = Crypt:Encrypt11g( password, bin.pack( "H", auth["AUTH_SESSKEY"] ), bin.pack("H", auth["AUTH_VFR_DATA"] ) )
		else
			sesskey_enc, auth_pass = Crypt:Encrypt10g( user, password, bin.pack( "H", auth["AUTH_SESSKEY"] ) )
		end

		status, data = self.comm:exchTNSPacket( Packet.Auth:new( user, auth_options, sesskey_enc, auth_pass, self.os ) )
		if ( not(status) ) then	return false, data end
		self.auth_session = data["AUTH_SESSION_ID"]
		return true
	end,

	--- Steal auth data from database
	-- @param user containing the Oracle user name
	-- @param pass containing the Oracle user password
	-- @return true on success, false on failure
	-- @return err containing error message when status is false
	StealthLogin = function( self, user, password )
		local data, packet, status, tns, parser
		local sesskey_enc, auth_pass, auth
		local auth_options = AuthOptions:new()

		status, auth = self.comm:exchTNSPacket( Packet.PreAuth:new( user, auth_options, self.os ) )
		if ( not(status) ) then
			return false, auth
		elseif ( auth["AUTH_SESSKEY"] ) then
			return true, auth
		else
			return false
		end
	end,
	
	--- Queries the database
	--
	-- @param query string containing the SQL query
	-- @return true on success, false on failure
	-- @return result table containing fields
	--          <code>rows</code>
	--          <code>columns</code>
	-- @return err containing error message when status is false
	Query = function(self, query)

		local SUPPORTED_VERSIONS = {
			"IBMPC/WIN_NT-8.1.0",
		}

		local status = false
		for _, ver in pairs(SUPPORTED_VERSIONS) do
			if ( self.os == ver ) then
				status = true
				break
			end
		end

		if ( not(status) ) then
			stdnse.print_debug(2, "ERROR: Version %s is not yet supported", self.os)
			return false, ("ERROR: Querying version %s is not yet supported"):format(self.os)
		end

		if ( not(query) ) then return false, "No query was supplied by user" end

		local data
		status, data = self.comm:exchTNSPacket( Packet.PostLogin:new(self.auth_session) )
		if ( not(status) ) then
			return false, "ERROR: Postlogin packet failed"
		end

		local status, result = self.comm:exchTNSPacket( Packet.Query:new(query) )
		if ( not(status) ) then	return false, result end

		if ( not(result.moredata) ) then return true, result.data end
		result = result.data

		repeat
			status, data = self.comm:exchTNSPacket( Packet.QueryResponseAck:new(result) )
		until(not(status) or data:match(".*ORA%-01403: no data found\n$"))

		return true, result
	end,

	--- Ends the Oracle communication
	Close = function( self )
		-- We should probably stick some slick sqlplus termination stuff in here
		local status = self.comm:sendTNSPacket( Packet.EOF:new( ) )
		self.socket:close()
	end,
	
}

return _ENV;
