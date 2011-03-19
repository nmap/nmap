---
-- TNS Library supporting a very limited subset of Oracle operations
--
-- Summary
-- -------
-- 	The library currently provides functionality to connect and authenticate
--  to the Oracle database server. It has currently been tested against and
--  known to work with Oracle 10G and Oracle 11G.
--
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
--		- Implements a number of functions to handle communication over the
--        the TNSSocket class.
--
--   o Crypt
-- 		- Implements encryption algorithms and functions to support 
--        authentication with Oracle 10G and Oracle 11G.
--
--   o Helper
--		- A helper class that provides easy access to the rest of the library
--
--   o TNSSocket
--      - This is a copy of the DB2Socket class which provides fundamental 
--        buffering
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
-- This implementation is tested and known to work against:
-- x Oracle 10g R2 on Windows
-- x Oracle 11g on Linux
-- x Oracle 11g R2 on Linux 
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"
--
-- @args tns.sid specifies the Oracle instance to connect to

--
-- Version 0.3
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/21/2010 - v0.2 - made minor changes to support 11gR2 on Windows
-- Revised 07/23/2010 - v0.3 - corrected incorrect example code in docs
--                           - removed ssl require

require 'bin'

module(... or "tns", package.seeall)

-- Make sure we have SSL support
local HAVE_SSL = false

if pcall(require,'openssl') then
  HAVE_SSL = true
  math.randomseed( select(2, bin.unpack(">L", openssl.rand_bytes(8))))
else
  math.randomseed( os.time() )
end


-- Oracle version constants
ORACLE_VERSION_10G = 313
ORACLE_VERSION_11G = 314

AuthOptions = 
{
		
	new = function( self )
		local o = {}
   		setmetatable(o, self)
    	self.__index = self

		o.auth_user = nil
		o.auth_term = "pts/" .. math.random(255)
		o.auth_prog = ("sqlplus@nmap_%d (TNS V1-V3)"):format(math.random(32768))
		o.auth_machine = "nmap_target"
		o.auth_pid = "" .. math.random(32768)
		o.auth_sid = "nmap_" .. math.random(32768)

		return o
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

	new = function( self, sock )
		local o = {}
   		setmetatable(o, self)
    	self.__index = self
		o.socket = sock
		return o
	end,
	
	--- Read a TNS packet of the socket
	--
	-- @return true on success, false on failure
	-- @return err string containing error message on failure
	recv = function( self )
		local _
		local status, data = self.socket:recv( 2 )

		if ( not(status) ) then
			return status, data
		end

		_, self.length = bin.unpack(">S", data )
		
		status, data = self.socket:recv( 6 ) -- self.length - 2 )
		if ( not(status) ) then
			return status, data
		end
		
		_, self.checksum, self.type, self.reserved, self.hdr_checksum = bin.unpack(">SCCS", data)
		
		status, data = self.socket:recv( self.length - 8)
		if ( status ) then
			self.data = data
		end
		
		return true
	end,
	
	--- Converts the TNS packet to string suitable to be sent over the socket
	--
	-- @return string containing the TNS packet
	toString = function( self )
		local data = bin.pack(">SSCCSA", self.length, self.checksum, self.type, 
										self.reserved, self.hdr_checksum, self.data )
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
		
		new = function( self, rhost, rport, dbinstance )
			local o = {}
	       	setmetatable(o, self)
	        self.__index = self
			o.rhost = rhost
			o.rport = rport
			o.conn_data = Packet.Connect.CONN_STR:format( rhost, rport, dbinstance, rhost )
			o.dbinstance = dbinstance:upper()
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
		toString = function( self )
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

	new = function( self, sock, data )
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.TNS = Packet.TNS:new( sock )
		o.TNS.type = Packet.TNS.Type.DATA
		o.socket = sock
		o.data = data
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet
	toString = function( self )
		local data = bin.pack( ">S", self.flag ) .. self.data
		
		self.TNS.length = #data + 8
		
		return self.TNS:toString() .. data
	end,
	
}

-- Packet received by the server to indicate errors or end of
-- communication.
Packet.Attention = {

	tns_type = Packet.TNS.Type.MARKER,

	new = function( self, typ, data )
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.att_type = typ
		o.data = data
		return o
	end,

	--- Converts the MARKER packet to string
	--
	-- @return string containing the packet	
	toString = function( self )
		return bin.pack( ">C", self.att_type ) .. self.data
	end,
		
}

-- Packet initializing challenge response authentication
Packet.PreAuth = {
	
	tns_type = Packet.TNS.Type.DATA,
	flags = 0,
		
	param_order = { 
		[1] = { ["AUTH_TERMINAL"] = "auth_term" },
		[2] = { ["AUTH_PROGRAM_NM"] = "auth_prog" },
		[3] = { ["AUTH_MACHINE"] = "auth_machine" },
		[4] = { ["AUTH_PID"] = "auth_pid" },
		[5] = { ["AUTH_SID"] = "auth_sid" }
	},
	
	
	--- Creates a new PreAuth packet
	--
	-- @param user string containing the user name
	-- @return a new instance of Packet.PreAuth
	new = function(self, user, options)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.auth_user = user
		o.auth_options = options
		return o
	end,
	
	--- Converts a parameter to a string representation
	--
	-- @param name string containing the parameter name
	-- @param value string containing the parameter value
	-- @return string containing the parameter key and value
	paramToString = function( self, param_name, param_value )
		return bin.pack(">CIACIAI", #param_name, #param_name, param_name, #param_value, #param_value, param_value, 0 )
	end,

	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	toString = function( self )
		local data = bin.pack("<SHIIH", self.flags, "037602feffffff", #self.auth_user, 1, "feffffff05000000fefffffffeffffff")
		data = data .. bin.pack("CA", #self.auth_user, self.auth_user )

		for _, v in ipairs( Packet.PreAuth.param_order ) do
			for k, v2 in pairs(v) do
				data = data .. self:paramToString( k, self.auth_options[v2] )
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

		local len, len2, key, val, _
		local pos = 6
		local kvps = {}

		while( true ) do
			pos, len, len2 = bin.unpack("<IC", tns.data, pos )
			if ( len ~= len2 ) then
				break
			end

			pos, key = bin.unpack("A" .. len, tns.data, pos )
			pos, len, _ = bin.unpack("<IC", tns.data, pos )
			pos, val = bin.unpack("A" .. len, tns.data, pos)
			pos = pos + 4

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
		[1] = { ['key'] = "AUTH_RTT", ['def'] = "25456" },
		[2] = { ['key'] = "AUTH_CLNT_MEM", ['def'] = "4096" },
		[3] = { ['key'] = "AUTH_TERMINAL", ['var'] = "auth_term" },
		[4] = { ['key'] = "AUTH_PROGRAM_NM", ['var'] = "auth_prog" },
		[5] = { ['key'] = "AUTH_MACHINE", ['var'] = "auth_machine" },
		[6] = { ['key'] = "AUTH_PID", ['var'] = "auth_pid" },
		[7] = { ['key'] = "AUTH_SID", ['var'] = "auth_sid" },
		[8] = { ['key'] = "SESSION_CLIENT_CHARSET", ['def'] = "1" },
		[9] = { ['key'] = "SESSION_CLIENT_LIBTYPE", ['def'] = "1" },
		[10] = { ['key'] = "SESSION_CLIENT_DRIVER_NAME", ['def'] = "" },
		[11] = { ['key'] = "SESSION_CLIENT_VERSION", ['def'] = "185599488" },
		[12] = { ['key'] = "SESSION_CLIENT_LOBATTR", ['def'] = "1" },
		[13] = { ['key'] = "AUTH_ACL", ['def'] = "4400" },
		[14] = { ['key'] = "AUTH_ALTER_SESSION", ['def'] = "ALTER SESSION SET TIME_ZONE='+02:00'\0" },
		[15] = { ['key'] = "AUTH_LOGICAL_SESSION_ID", ['def'] = select(2, bin.unpack("H16", openssl.rand_pseudo_bytes(16))) },
		[16] = { ['key'] = "AUTH_FAILOVER_ID", ['def'] = "" },
	},

	--- Creates a new Auth packet
	--
	-- @param auth_sesskey the encrypted session key
	-- @param auth_pass the encrypted user password
	-- @return a new instance of Packet.Auth
	new = function(self, user, options, auth_sesskey, auth_pass)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.auth_sesskey = auth_sesskey
		o.auth_pass = auth_pass
		o.auth_options = options
		o.user = user
		return o
	end,

	--- Converts a parameter to a string representation
	--
	-- @param name string containing the parameter name
	-- @param value string containing the parameter value
	-- @return string containing the parameter key and value
	paramToString = function( self, param_name, param_value )
		if ( not( param_value ) or #param_value == 0 ) then
			return bin.pack(">CIAII", #param_name, #param_name, param_name, #param_value, 0 )			
		else
			return bin.pack(">CIACIAI", #param_name, #param_name, param_name, #param_value, #param_value, param_value, 0 )
		end
	end,

	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	toString = function( self )
		
		local sess_id = select(2, bin.unpack("H16", openssl.rand_pseudo_bytes(16)))
		local data = bin.pack(">SHCHpHAHAH", self.flags, "037303feffffff", 
								#self.user, "00000001010000feffffff12000000fefffffffeffffff", 
								self.user, "0c0000000c415554485f534553534b455960000000fe40",
								self.auth_sesskey, "00010000000d0000000d415554485f50415353574f52444000000040",
								self.auth_pass, "00000000") 
								
		for k, v in ipairs( self.param_order ) do
			if ( v['def'] ) then
				data = data .. self:paramToString( v['key'], v['def'])
			elseif ( self.auth_options[ v['var'] ] ) then
				data = data .. self:paramToString(  v['key'], self.auth_options[ v['var'] ] )
			elseif ( self[ v['var'] ] ) then
				data = data .. self:paramToString(  v['key'], self[ v['var'] ] )
			end
		end
		

		return data 
	end
}

Packet.SNS = {
	
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
	toString = function( self )
		return  bin.pack("SH", self.flags, "deadbeef00920b1006000004000004000300000000000400050b10060000080001000015cb353abecb00120001" .. 
				    		 	  "deadbeef00030000000400040001000100020001000300000000000400050b10060000020003e0e100020006fc" ..
								  "ff0002000200000000000400050b100600000c0001001106100c0f0a0b08020103000300020000000000040005" ..
								  "0b10060000030001000301" )
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
	toString = function( self )
		local pfx = bin.pack(">SH", self.flags, "0106050403020100")
		return pfx .. "Linuxi386/Linux-2.0.34-8.1.0\0"		
	end,		

	--- Parses and verifies the server response
	--
	-- @param tns Packet.TNS containing the response from the server
	parseResponse = function( self, tns )
		local flags, neg, ver, srv, pos, _
	
		pos, flags, neg, ver, _, srv = bin.unpack(">SCCCz", tns.data)
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
		local o = {}
       	setmetatable(o, self)
		o.os = os
        self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	toString = function( self )

		if (  self.os:match("IBMPC/WIN_NT[-]8.1.0") ) then
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
	
	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	--- Converts the DATA packet to string
	--
	-- @return string containing the packet	
	toString = function( self )
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
	toString = function( self )
		return bin.pack(">S", self.flags )
	end	
}

-- The TNS communication class uses the TNSSocket to transmit data
Comm = {
	
	--- Creates a new instance of the Comm class
	--
	-- @param socket containing a TNSSocket
	-- @return new instance of Comm
	new = function(self, socket)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.tnssocket = socket
		return o
	end,

	--- Attemts to send a TNS packet over the socket
	--
	-- @param pkt containing an instance of a Packet.*
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	sendTNSPacket = function( self, pkt )

		local tns = Packet.TNS:new( self.tnssocket )
		tns.type = pkt.tns_type
		tns.data = pkt:toString()
		tns.length = #tns.data + 8
		
		-- buffer incase of RESEND
		self.pkt = pkt
		
		return self.tnssocket:send( tns:toString() )
	end,

	--- Handles communication when a MARKER packet is recieved and retrieves
	--  the following error message
	--
	-- @return false always to indicate that an error occured
	-- @return msg containing the error message
	handleMarker = function( self )
		local status, tns = self:recvTNSPacket()
		local pos, msg, b1
		
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
		pos, b1 = bin.unpack("C", tns.data, 10)
		
		if( b1 == 1) then
			pos = 99
		else
			pos = 69
		end
		
		-- fetch the oracle error and return it
		pos, msg = bin.unpack("p", tns.data, pos )

		return false, msg		
	end,
	
	--- Recieves a TNS packet and handles TNS-resends
	--
	-- @return status true on success, false on failure
	-- @return tns Packet.TNS containing the recieved packet or err on failure
	recvTNSPacket = function( self )
		local tns = Packet.TNS:new( self.tnssocket )
		local retries = 5
		
		repeat
			local status = tns:recv()
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
		local enc, iv2, hash

		-- do padding
		if ( #uspw % 8 > 0 ) then
			for i=1,(8-(#uspw % 8)) do
				uspw = uspw .. "\0"
			end
		end

		iv2 = openssl.encrypt( "DES-CBC", key, nil, uspw, false ):sub(-8)
		enc = openssl.encrypt( "DES-CBC", iv2, nil, uspw, false ):sub(-8)
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
		combined_sesskey= openssl.md5( combined_sesskey )
		
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
		combined_sesskey= openssl.md5( combined_sesskey )
		
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
		cli_sesskey_enc = cli_sesskey_enc:sub(1, 64) .. " " .. cli_sesskey_enc:sub(65)

		auth_password = openssl.encrypt( "aes-192-cbc", combined_sesskey, nil, rnd .. pass, true )
		auth_password = select(2, bin.unpack("H" .. #auth_password, auth_password))
		
		return cli_sesskey_enc, auth_password
	end,
	
}

Helper = {
				
	new = function(self, host, port, instance )
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.tnssocket = TNSSocket:new()
		o.dbinstance = instance or nmap.registry.args['tns.sid'] or "orcl"
		return o
	end,
	
	--- Connects and performs protocol negotiation with the Oracle server
	--
	-- @return true on success, false on failure
	-- @return err containing error message when status is false
	Connect = function( self )
		local status, data = self.tnssocket:connect( self.host.ip, self.port.number, "tcp" )
		local conn, packet, tns

		if( not(status) ) then
			return status, data
		end
		
		self.comm = Comm:new( self.tnssocket )
											
		status, self.version = self.comm:exchTNSPacket( Packet.Connect:new( self.host.ip, self.port.number, self.dbinstance ) )
		if ( not(status) ) then
			return false, self.version
		end

		if ( self.version ~= ORACLE_VERSION_11G and self.version ~= ORACLE_VERSION_10G ) then
			return false, ("Unsupported Oracle Version (%d)"):format(self.version)
		end
						
		status = self.comm:exchTNSPacket( Packet.SNS:new( self.version ) )
		if ( not(status) ) then
			return false, "ERROR: Helper.Connect failed"
		end
				
		status, self.os = self.comm:exchTNSPacket( Packet.ProtoNeg:new( self.version ) )
		if ( not(status) ) then
			return false, data
		end

		if ( self.os:match("IBMPC/WIN_NT[-]8.1.0") ) then
			status = self.comm:sendTNSPacket( Packet.Unknown1:new( self.os ) )
			if ( not(status) ) then
				return false, "ERROR: Helper.Connect failed"
			end			
			status, data = self.comm:sendTNSPacket( Packet.Unknown2:new( ) )
			if ( not(status) ) then
				return false, data
			end			
			status, data = self.comm:recvTNSPacket( Packet.Unknown2:new( ) )
			if ( not(status) ) then
				return false, data
			end			
			-- Oracle 10g under Windows needs this additional read, there's
			-- probably a better way to detect this by analysing the packets
			-- further.
			if ( self.version == ORACLE_VERSION_10G ) then
				status, data = self.comm:recvTNSPacket( Packet.Unknown2:new( ) )
				if ( not(status) ) then
					return false, data
				end			
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
		local status, data = self.tnssocket:connect( self.host.ip, self.port.number, "tcp" )
		local conn, packet, tns, pkt

		if( not(status) ) then
			return status, data
		end
		
		self.comm = Comm:new( self.tnssocket )
								
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

		status, auth = self.comm:exchTNSPacket( Packet.PreAuth:new( user, auth_options ) )
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
			
		status, data = self.comm:exchTNSPacket( Packet.Auth:new( user, auth_options, sesskey_enc, auth_pass ) )
		if ( not(status) ) then
			return false, data
		end

		return true;
	end,

	--- Ends the Oracle communication
	Close = function( self )
		-- We should probably stick some slick sqlplus termination stuff in here
		local status = self.comm:sendTNSPacket( Packet.EOF:new( ) )
		self.tnssocket:close()
	end,
	
}

-- copy paste of DB2Socket aka VNCSocket
TNSSocket =
{	

	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.Socket = nmap.new_socket()
		-- We need this massive timeout due to Oracle 11g throttling of
		-- repeated login attempts.
		o.Socket:set_timeout(30000)
		o.Buffer = nil
		return o
	end,
	

	--- Establishes a connection.
	--
	-- @param hostid Hostname or IP address.
	-- @param port Port number.
	-- @param protocol <code>"tcp"</code>, <code>"udp"</code>, or
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	connect = function( self, hostid, port, protocol )
		-- Attempt to catch this as early as possible
		if ( not(HAVE_SSL) ) then
			return false, "This module requires OpenSSL"
		end
		return self.Socket:connect( hostid, port, protocol )
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
			if ( not(status) ) then
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