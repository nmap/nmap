---
-- MSSQL Library supporting a very limited subset of operations.
--
-- The library was designed and tested against Microsoft SQL Server 2005.
-- However, it should work with versions 7.0, 2000, 2005 and 2008. 
-- Only a minimal amount of parsers have been added for tokens, column types
-- and column data in order to support the first scripts.
-- 
-- The code has been implemented based on traffic analysis and the following
-- documentation:
-- * SSRP Protocol Specification: http://msdn.microsoft.com/en-us/library/cc219703.aspx
-- * TDS Protocol Documentation: http://www.freetds.org/tds.html.
-- * The JTDS source code: http://jtds.sourceforge.net/index.html.
--
-- * ColumnInfo: Class containing parsers for column types which are present before the row data in all query response packets. The column information contains information relevant to the data type used to hold the data eg. precision, character sets, size etc.
-- * ColumnData: Class containing parsers for the actual column information.
-- * Token: Class containing parsers for tokens returned in all TDS responses. A server response may hold one or more tokens with information from the server. Each token has a type which has a number of type specific fields.
-- * QueryPacket: Class used to hold a query and convert it to a string suitable for transmission over a socket.
-- * LoginPacket: Class used to hold login specific data which can easily be converted to a string suitable for transmission over a socket.
-- * TDSStream: Class that handles communication over the Tabular Data Stream protocol used by SQL serve. It is used to transmit the the Query- and Login-packets to the server.
-- * Helper: Class which facilitates the use of the library by through action oriented functions with descriptive names.
-- * Util: A "static" class containing mostly character and type conversion functions.
--
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
-- local helper = mssql.Helper:new()
-- status, result = helper:Login( username, password, "temdpb", host.ip )
-- status, result = helper:Query( "SELECT name FROM master..syslogins")
-- helper:Disconnect()
-- <code>
--
-- Known limitations:
-- * The library does not support SSL. The foremost reason being the akward choice of implementation where the SSL handshake is performed within the TDS data block. By default, servers support connections over non SSL connections though. 
-- * Version 7 and ONLY version 7 of the protocol is supported. This should cover Microsoft SQL Server 7.0 and later.
-- * TDS Responses contain one or more response tokens which are parsed based on their type. The supported tokens are listed in the <code>TokenType</code> table and their respective parsers can be found in the <code>Token</code> class. Note that some token parsers are not fully implemented and simply move the offset the right number of bytes to continue processing of the response.
-- * The library only supports a limited subsets of datatypes and will abort execution and return an error if it detects an unsupported type. The supported data types are listed in the <code>DataTypes</code> table. In order to add additional data types a parser function has to be added to both the <code>ColumnInfo</code> and <code>ColumnData</code> class.
-- * No functionality for languages, localization or characted codepages has been considered or implemented.
-- * The library does database authentication only. No OS authentication or use of the integrated security model is supported.
-- * Queries using SELECT, INSERT, DELETE and EXEC of procedures have been tested while developing scripts.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- 
-- @args mssql.timeout How long to wait for SQL responses. This is a number
-- followed by <code>ms</code> for milliseconds, <code>s</code> for seconds,
-- <code>m</code> for minutes, or <code>h</code> for hours. Default:
-- <code>30s</code>.

module(... or "mssql", package.seeall)

-- Version 0.2
-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 03/28/2010 - v0.2 - fixed incorrect token types. added 30 seconds timeout
-- Revised 01/23/2011 - v0.3 - fixed parsing error in discovery code with patch
--							   from Chris Woodbury

require("bit")
require("bin")
require("stdnse")

do
  local arg = nmap.registry.args and nmap.registry.args["mssql.timeout"] or "30s"
  local timeout, err

  timeout, err = stdnse.parse_timespec(arg)
  if not timeout then
    error(err)
  end
  MSSQL_TIMEOUT = timeout
end

-- TDS packet types
PacketType =
{
	Query = 0x01,
	Response = 0x04,
	Login = 0x10,
}

-- TDS response token types
TokenType = 
{
	TDS7Results = 0x81,
	ErrorMessage = 0xAA,
	InformationMessage = 0xAB,
	LoginAcknowledgement = 0xAD,
	Row = 0xD1,
	OrderBy = 0xA9,
	EnvironmentChange = 0xE3,
	Done = 0xFD,
	DoneInProc = 0xFF,
}

-- SQL Server/Sybase data types
DataTypes = 
{
	SYBINTN = 0x26,
	SYBINT2 = 0x34,
	SYBINT4 = 0x38,
	SYBDATETIME = 0x3D,
	SYBDATETIMN = 0x6F,
	XSYBVARBINARY = 0xA5,
	XSYBVARCHAR = 0xA7,
	XSYBNVARCHAR = 0xE7,
}

-- "static" ColumInfo parser class
ColumnInfo = 
{

	Parse =
	{
		[DataTypes.XSYBNVARCHAR] = function( data, pos )
			local colinfo = {}
			local tmp
			
			pos, colinfo.lts, colinfo.codepage, colinfo.flags, colinfo.charset, 
			colinfo.msglen = bin.unpack("<SSSCC", data, pos )
			pos, tmp = bin.unpack("A" .. (colinfo.msglen * 2), data, pos)
			colinfo.text = Util.FromWideChar(tmp)
		
			return pos, colinfo
		end,
		
		[DataTypes.SYBINT2] = function( data, pos )
			return ColumnInfo.Parse[DataTypes.SYBDATETIME](data, pos)
		end,
		
		[DataTypes.SYBINTN] = function( data, pos )
			local colinfo = {}
			local tmp

			pos, colinfo.unknown, colinfo.msglen = bin.unpack("<CC", data, pos)
			pos, tmp = bin.unpack("A" .. (colinfo.msglen * 2), data, pos )
			colinfo.text = Util.FromWideChar(tmp)
			
			return pos, colinfo
		end,
		
		[DataTypes.SYBINT4] = function( data, pos )
			return ColumnInfo.Parse[DataTypes.SYBDATETIME](data, pos)
		end,
		
		[DataTypes.XSYBVARBINARY] = function( data, pos )
			local colinfo = {}
			local tmp

			pos, colinfo.lts, colinfo.msglen = bin.unpack("<SC", data, pos)
			pos, tmp = bin.unpack("A" .. (colinfo.msglen * 2), data, pos )
			colinfo.text = Util.FromWideChar(tmp)
			
			return pos, colinfo
		end,
		
		[DataTypes.SYBDATETIME] = function( data, pos )
			local colinfo = {}
			local tmp
		
			pos, colinfo.msglen = bin.unpack("C", data, pos)
			pos, tmp = bin.unpack("A" .. (colinfo.msglen * 2), data, pos )
			colinfo.text = Util.FromWideChar(tmp)
	
			return pos, colinfo
		end,
		
		[DataTypes.SYBDATETIMN] = function( data, pos )
			return ColumnInfo.Parse[DataTypes.SYBINTN](data, pos)
		end,
		
		[DataTypes.XSYBVARCHAR] = function( data, pos )
			return ColumnInfo.Parse[DataTypes.XSYBNVARCHAR](data, pos)
		end,
			
	}
	
}

-- "static" ColumData parser class
ColumnData = 
{
	Parse = {
		
		[DataTypes.XSYBNVARCHAR] = function( data, pos )
			local size, coldata
			
			pos, size = bin.unpack( "<S", data, pos )
			pos, coldata = bin.unpack( "A"..size, data, pos )

			return pos, Util.FromWideChar(coldata)
		end,
		
		[DataTypes.XSYBVARCHAR] = function( data, pos )
			local size, coldata
			
			pos, size = bin.unpack( "<S", data, pos )
			pos, coldata = bin.unpack( "A"..size, data, pos )

			return pos, coldata
		end,

		[DataTypes.XSYBVARBINARY] = function( data, pos )
			local coldata, size

			pos, size = bin.unpack( "<S", data, pos )
			pos, coldata = bin.unpack( "A"..size, data, pos )
			
			return pos, "0x" .. select(2, bin.unpack("H"..coldata:len(), coldata ) )
		end,
		
		[DataTypes.SYBINT4] = function( data, pos )
			local num
			pos, num = bin.unpack("<I", data, pos)
			
			return pos, num
		end,

		[DataTypes.SYBINT2] = function( data, pos )
			local num
			pos, num = bin.unpack("<S", data, pos)
			
			return pos, num
		end,
		
		[DataTypes.SYBINTN] = function( data, pos )
			local len, num
			pos, len = bin.unpack("C", data, pos)

			if ( len == 1 ) then
				return bin.unpack("C", data, pos)
			elseif ( len == 2 ) then
				return bin.unpack("<S", data, pos)
			elseif ( len == 4 ) then
				return bin.unpack("<I", data, pos)
			elseif ( len == 8 ) then
				return bin.unpack("<L", data, pos)
			else
				return -1, ("Unhandled length (%d) for SYBINTN"):format(len)
			end

			return -1, "Error"
		end,
		
		[DataTypes.SYBDATETIME] = function( data, pos )
			local hi, lo, dt, result
			pos, hi, lo = bin.unpack("<II", data, pos)

			-- CET 01/01/1900
			dt = -2208996000
			result = os.date("%x %X", dt + (hi*24*60*60) + (lo/300) )
			
			return pos, result
		end,

		[DataTypes.SYBDATETIMN] = function( data, pos )
			return ColumnData.Parse[DataTypes.SYBINTN]( data, pos )
		end,

	}
}

-- "static" Token parser class
Token = 
{

	Parse = {
		--- Parse error message tokens
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields
		[TokenType.ErrorMessage] = function( data, pos )
			local token = {}
			local tmp

			token.type = TokenType.ErrorMessage
			pos, token.size, token.errno, token.state, token.severity, token.errlen = bin.unpack( "<SICCS", data, pos )
			pos, tmp = bin.unpack("A" .. (token.errlen * 2), data, pos )
			token.error = Util.FromWideChar(tmp)
			pos, token.srvlen = bin.unpack("C", data, pos)
			pos, tmp = bin.unpack("A" .. (token.srvlen * 2), data, pos )
			token.server = Util.FromWideChar(tmp)
			pos, token.proclen = bin.unpack("C", data, pos)
			pos, tmp = bin.unpack("A" .. (token.proclen * 2), data, pos )
			token.proc = Util.FromWideChar(tmp)
			pos, token.lineno = bin.unpack("<S", data, pos)

			return pos, token
		end,
		
		--- Parse environment change tokens
		-- (This function is not implemented and simply moves the pos offset)
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields		
		[TokenType.EnvironmentChange] = function( data, pos )
			local token = {}
			local tmp
			
			token.type = TokenType.EnvironmentChange
			pos, token.size = bin.unpack("<S", data, pos)
		
			return pos + token.size, token
		end,
	
		--- Parse information message tokens
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields		
		[TokenType.InformationMessage] = function( data, pos )
			local pos, token = Token.Parse[TokenType.ErrorMessage]( data, pos )
			token.type = TokenType.InformationMessage
			return pos, token
		end,
	
		--- Parse login acknowledgment tokens
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields			
		[TokenType.LoginAcknowledgement] = function( data, pos )
			local token = {}
			local _
			
			-- don't do much, just increase the pos offset to next token
			token.type = TokenType.LoginAcknowledgement
			pos, token.size, _, _, _, _, token.textlen = bin.unpack( "<SCCCSC", data, pos )
			pos, token.text = bin.unpack("A" .. token.textlen * 2, data, pos)
			pos, token.version = bin.unpack("<I", data, pos )

			return pos, token
		end,
	
		--- Parse done tokens
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields			
		[TokenType.Done] = function( data, pos )
			local token = {}
			local _
			
			-- don't do much, just increase the pos offset to next token
			token.type = TokenType.Done
			pos, token.flags, token.operation, token.rowcount = bin.unpack( "<SSI", data, pos )
			
			return pos, token
		end,
		
		--- Parses a DoneInProc token recieved after executing a SP
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields				
		[TokenType.DoneInProc] = function( data, pos )
			local token
			pos, token = Token.Parse[TokenType.Done]( data, pos )
			token.type = TokenType.DoneInProc
			
			return pos, token
		end,
		
		--- Parses a OrderBy token
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields						
		[TokenType.OrderBy] = function( data, pos )
			local token = {}
			
			pos, token.size = bin.unpack("<S", data, pos)
			token.type = TokenType.OrderBy
			return pos + token.size, token
		end,

		
		--- Parse TDS result tokens
		--
		-- @param data string containing "raw" data
		-- @param pos number containing offset into data
		-- @return pos number containing new offset after parse
		-- @return token table containing token specific fields			
		[TokenType.TDS7Results] = function( data, pos )
			local token = {}
			local _
			
			token.type = TokenType.TDS7Results
			pos, token.count = bin.unpack( "<S", data, pos )
			token.colinfo = {}
			
			for i=1, token.count do
				local colinfo = {}
				local usertype, flags, ttype
				
				pos, usertype, flags, ttype = bin.unpack("<SSC", data, pos )
				if ( not(ColumnInfo.Parse[ttype]) ) then
					return -1, ("Unhandled data type: 0x%X"):format(ttype)
				end
								
				pos, colinfo = ColumnInfo.Parse[ttype]( data, pos )
				
				colinfo.usertype = usertype
				colinfo.flags = flags
				colinfo.type = ttype
				
				table.insert( token.colinfo, colinfo )
			end
			return pos, token
		end,
	},
	
	--- Parses the first token at positions pos
	--
	-- @param data string containing "raw" data
	-- @param pos number containing offset into data
	-- @return pos number containing new offset after parse or -1 on error
	-- @return token table containing token specific fields	or error message on error		
	ParseToken = function( data, pos )
		local ttype
		pos, ttype = bin.unpack("C", data, pos)
		if ( not(Token.Parse[ttype]) ) then
			return -1, ("No parser for token type: 0x%X"):format( ttype )
		end
			
		return Token.Parse[ttype](data, pos)
	end,
	
}


--- QueryPacket class
QueryPacket = 
{
	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	SetQuery = function( self, query )
		self.query = query
	end,
	
	--- Returns the query packet as string
	--
	-- @return string containing the authentication packet
	ToString = function( self )
		return PacketType.Query, Util.ToWideChar( self.query )
	end,
	
}


--- LoginPacket class
LoginPacket = 
{
	
	-- options_1 possible values
	-- 0x80 enable warning messages if SET LANGUAGE issued
    -- 0x40 change to initial database must succeed
    -- 0x20 enable warning messages if USE <database> issued
    -- 0x10 enable BCP
    
	-- options_2 possible values
    -- 0x80 enable domain login security
	-- 0x40 "USER_SERVER - reserved" 
	-- 0x20 user type is "DQ login"
	-- 0x10 user type is "replication login"
	-- 0x08 "fCacheConnect"
	-- 0x04 "fTranBoundary"
    -- 0x02 client is an ODBC driver
    -- 0x01 change to initial language must succeed
	length = 0,
	version = 0x71000001, -- Version 7.1
	size = 0,
	cli_version = 7, -- From jTDS JDBC driver
	cli_pid = 0, -- Dummy value
	conn_id = 0,
	options_1 = 0xa0,
	options_2 = 0x03,
	sqltype_flag = 0,
	reserved_flag= 0,
	time_zone = 0,
	collation = 0,

	-- Strings
	client = "Nmap",
	username = nil,
	password = nil,
	app = "Nmap NSE",
	server = nil,
	library = "mssql.lua",
	locale = "",
	database = "master", --nil,
	MAC = string.char(0x00,0x00,0x00,0x00,0x00,0x00), -- should contain client MAC, jTDS uses all zeroes
	
	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	--- Sets the username used for authentication
	--
	-- @param username string containing the username to user for authentication
	SetUsername = function(self, username)
		self.username = username
	end,

	--- Sets the password used for authentication
	--
	-- @param password string containing the password to user for authentication	
	SetPassword = function(self, password)
		self.password = password
	end,
	
	--- Sets the database used in authentication
	--
	-- @param database string containing the database name
	SetDatabase = function(self, database)
		self.database = database
	end,

	--- Sets the server's name used in authentication
	--
	-- @param server string containing the name	or ip of the server
	SetServer = function(self, server)
		self.server = server
	end,
	
	--- Returns the authentication packet as string
	--
	-- @return string containing the authentication packet
	ToString = function(self)
		local data
		local offset = 86
		
		self.cli_pid = math.random(100000)
		
		self.length = offset + 2 * ( self.client:len() + self.username:len() + self.password:len() + 
								self.app:len() + self.server:len() + self.library:len() + self.database:len() )
								
		data = bin.pack("<IIIIII", self.length, self.version, self.size, self.cli_version, self.cli_pid, self.conn_id )
		data = data .. bin.pack("CCCC", self.options_1, self.options_2, self.sqltype_flag, self.reserved_flag )
		data = data .. bin.pack("<II", self.time_zone, self.collation )
		
		-- offsets begin
		data = data .. bin.pack("<SS", offset, self.client:len() )
		offset = offset + self.client:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.username:len() )
		offset = offset + self.username:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.password:len() )
		offset = offset + self.password:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.app:len() )
		offset = offset + self.app:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.server:len() )
		offset = offset + self.server:len() * 2
		
		-- unknown1 offset
		data = data .. bin.pack("<SS", 0, 0 )

		data = data .. bin.pack("<SS", offset, self.library:len() )
		offset = offset + self.library:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.locale:len() )
		offset = offset + self.locale:len() * 2
		
		data = data .. bin.pack("<SS", offset, self.database:len() )
		offset = offset + self.database:len() * 2

		-- client MAC address, hardcoded to 00:00:00:00:00:00
		data = data .. bin.pack("A", self.MAC)
		
		-- offset to auth info
		data = data .. bin.pack("<S", offset)
		-- lenght of nt auth (should be 0 for sql auth)
		data = data .. bin.pack("<S", 0)
		-- next position (same as total packet length)
		data = data .. bin.pack("<S", self.length)
		-- zero pad
		data = data .. bin.pack("<S", 0)
		
		-- Auth info wide strings
		data = data .. bin.pack("A", Util.ToWideChar(self.client) )
		data = data .. bin.pack("A", Util.ToWideChar(self.username) )
		data = data .. bin.pack("A", self.TDS7CryptPass(self.password) )
		data = data .. bin.pack("A", Util.ToWideChar(self.app) )
		data = data .. bin.pack("A", Util.ToWideChar(self.server) )
		data = data .. bin.pack("A", Util.ToWideChar(self.library) )
		data = data .. bin.pack("A", Util.ToWideChar(self.locale) )
		data = data .. bin.pack("A", Util.ToWideChar(self.database) )
		
		return PacketType.Login, data
	end,
	
	--- Encrypts a password using the TDS7 *ultra secure* XOR encryption
	--
	-- @param password string containing the password to encrypt
	-- @return string containing the encrypted password
	TDS7CryptPass = function(password)
		local xormask = 0x5a5a
		local result = ""
		
		for i=1, password:len() do
			local c = bit.bxor( string.byte( password:sub( i, i ) ), xormask )
			local m1= bit.band( bit.rshift( c, 4 ), 0x0F0F )
			local m2= bit.band( bit.lshift( c, 4 ), 0xF0F0 )
			result = result .. bin.pack("S", bit.bor( m1, m2 ) )
		end
		return result
	end,
	
}

-- Handles communication with SQL Server
TDSStream = {

	packetno = 0,

	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,

	--- Establishes a connection to the SQL server
	--
	-- @param host table containing host information
	-- @param port table containing port information
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Connect = function( self, host, port )
		local status, result, lport, _
		
		self.socket = nmap.new_socket()

		-- Set the timeout to something realistic for connects
		self.socket:set_timeout( 5000 )
		status, result = self.socket:connect(host, port)
		if ( not(status) ) then return false, "Connect failed" end

		-- Sometimes a Query can take a long time to respond, so we set
		-- the timeout to 30 seconds. This shouldn't be a problem as the
		-- library attempt to decode the protocol and avoid reading past 
		-- the end of the input buffer. So the only time the timeout is
		-- triggered is when waiting for a response to a query.
		self.socket:set_timeout( MSSQL_TIMEOUT * 1000 )

		status, _, lport, _, _ = self.socket:get_info()
		if ( status ) then
			math.randomseed(os.time() * lport )
		else
			math.randomseed(os.time() )
		end
		
		if ( not(status) ) then
			return false, "Socket connection failed"
		end
		
		return status, result
	end,

	--- Disconnects from the SQL Server
	--
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Disconnect = function( self )
		local status, result = self.socket:close()
		self.socket = nil
		return status, result
	end,
	
	--- Sets the timeout for communication over the socket
	--
	-- @param timeout number containing the new socket timeout in ms
	SetTimeout = function( self, timeout )
		self.socket:set_timeout(timeout)
	end,
	
	--- Send a TDS request to the server
	--
	-- @param pkt_type number containing the type of packet to send
	-- @param data string containing the raw data to send to the server
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Send = function( self, pkt_type, data )
		local len = data:len() + 8
		local last, channel, window = 1, 0, 0
		local packet
		
		self.packetno = self.packetno + 1
		packet = bin.pack(">CCSSCCA", pkt_type, last, len, channel, self.packetno, window, data )
		return self.socket:send( packet )
	end,

	--- Recieves responses from SQL Server
	-- The function continues to read and assemble a response until the server
	-- responds with the last response flag set
	--
	-- @return status true on success, false on failure
	-- @return result containing raw data contents or error message on failure
	Receive = function( self )
		local status 
		local pkt_type, last, size, channel, packet_no, window, tmp, needed
		local data, response = "", ""
		local pos = 1
		
		repeat
			if( response:len() - pos < 4 ) then
				status, tmp = self.socket:receive_bytes(4)
				response = response .. tmp
			end

			if ( not(status) ) then
				return false, "Failed to receive packet from MSSQL server"
			end

			pos, pkt_type, last, size = bin.unpack(">CCS", response, pos )
			if ( pkt_type ~= PacketType.Response ) then
				return false, "Server returned invalid packet"
			end

			needed = size - ( response:len() - pos + 5 )
			if ( needed > 0 ) then
				status, tmp = self.socket:receive_bytes(needed)
				if ( not(status) ) then
					return false, "Failed to receive packet from MSSQL server"
				end
				response = response .. tmp
				
			end
			pos, channel, packet_no, window, tmp = bin.unpack(">SccA" .. ( size - 8 ), response, pos)
			data = data .. tmp
		until last == 1
			
		-- return only the data section ie. without the headers
		return status, data
	end,
	
}

--- Helper class
Helper =
{
	new = function(self,o)
		o = o or {}
        setmetatable(o, self)
        self.__index = self
		return o
    end,
	
	--- Establishes a connection to the SQL server
	--
	-- @param host table containing host information
	-- @param port table containing port information
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Connect = function( self, host, port )
		local status, result
		self.stream = TDSStream:new()
		status, result = self.stream:Connect(host, port)
		if ( not(status) ) then
			return false, result
		end

		return true
	end,
	
	--- Sends a broadcast message to the SQL Browser Agent and parses the
	-- results. The response is returned as an array of tables representing
	-- each database instance. The tables have the following fields:
	-- <code>servername</code> - the server name
	-- <code>name</code> - the name of the instance
	-- <code>clustered</code> - is the server clustered?
	-- <code>version</code> - the db version, WILL MOST LIKELY BE INCORRECT
	-- <code>port</code> - the TCP port of the server
	-- <code>pipe</code> - the location of the listening named pipe
	-- <code>ip</code> - the IP of the server
	--
	-- @param host table as received by the script action function
	-- @param port table as received by the script action function
	-- @param broadcast boolean true if the discovery should be performed
	--        against the broadcast address or not.
	-- @return status boolean, true on success false on failure
	-- @return instances array of instance tables
	Discover = function( host, port, broadcast )
		local socket = nmap.new_socket("udp")
		local instances = {}
		
		-- set a reasonable timeout
		socket:set_timeout(5000)
		
		local status, err
		
		if ( not(broadcast) ) then
			status, err = socket:connect( host, port )
			if ( not(status) ) then	return false, err end
			status, err = socket:send("\002")
			if ( not(status) ) then	return status, err end
		else
			status, err = socket:sendto(host, port, "\002")			
		end
		
		local data
		
		repeat
			status, data = socket:receive()
			if ( not(status) ) then break end

			-- strip of first 3 bytes as they contain thing we don't want
			data = data:sub(4)
			
			local _, ip
			status, _, _, ip, _ = socket:get_info()
			
			
			-- It would seem easier to just capture (.-;;) repeateadly, since
			-- each instance ends with ";;", but ";;" can also occur within the
			-- data, signifying an empty field (e.g. "...bv;;@COMPNAME;;tcp;1433;;...").
			-- So, instead, we'll split up the string ahead of time.
			-- See the SSRP specification for more details.
			local instanceStrings = {}
			
			local firstInstanceEnd, instanceString
			repeat
				firstInstanceEnd = data:find( ";ServerName;(.-);InstanceName;(.-);IsClustered;(.-);" )
				if firstInstanceEnd then
					instanceString = data:sub( 1, firstInstanceEnd )
					data = data:sub( firstInstanceEnd + 1 )
				else
					instanceString = data
				end
				
				table.insert( instanceStrings, instanceString )
			until (not firstInstanceEnd)
			
			for _, instance in ipairs( instanceStrings ) do
				instances[ip] = instances[ip] or {}

		  		local info = {}
		  		info.servername = string.match(instance, "ServerName;(.-);")
		  		info.name = string.match(instance, "InstanceName;(.-);")
		  		info.clustered = string.match(instance, "IsClustered;(.-);")
		  		info.version = string.match(instance, "Version;(.-);")
		  		info.port = string.match(instance, ";tcp;(.-);")
		  		info.pipe = string.match(instance, ";np;(.-);")
				info.ip = ip
				
				if ( not(instances[ip][info.name]) ) then
					instances[ip][info.name] = info
				end
			end
		until( not(broadcast) )
		socket:close()
		
		return true, instances
	end,

	--- Disconnects from the SQL Server
	--
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Disconnect = function( self )
		if ( not(self.stream) ) then
			return false, "Not connected to server"
		end
		
		self.stream:Disconnect()
		self.stream = nil
		
		return true
	end,
	
	--- Authenticates to SQL Server
	--
	-- @param username string containing the username for authentication
	-- @param password string containing the password for authentication
	-- @param database string containing the database to access
	-- @param servername string containing the name or ip of the remote server
	-- @return status true on success, false on failure
	-- @return result containing error message on failure
	Login = function( self, username, password, database, servername )
		local loginPacket = LoginPacket:new()
		local status, result, data, token
		local servername = servername or "DUMMY"
		local pos = 1
		
		if ( nil == self.stream ) then
			return false, "Not connected to server"
		end

		loginPacket:SetUsername(username)
		loginPacket:SetPassword(password)
		loginPacket:SetDatabase(database)
		loginPacket:SetServer(servername)
		
		status, result = self.stream:Send( loginPacket:ToString() )
		if ( not(status) ) then
			return false, result
		end

		status, data = self.stream:Receive()
		if ( not(status) ) then
			return false, data
		end

		while( pos < data:len() ) do
			pos, token = Token.ParseToken( data, pos )
			if ( -1 == pos ) then
				return false, token
			end
			-- Let's check for user must change password, it appears as if this is
			-- reported as ERROR 18488		
			if ( token.type == TokenType.ErrorMessage and token.errno == 18488 ) then
				return false, "Must change password at next logon"
			elseif ( token.type == TokenType.LoginAcknowledgement ) then
				return true, "Login Success"
			end
		end

		return false, "Login Failed"
	end,
	
	--- Performs a SQL query and parses the response
	--
	-- @param query string containing the SQL query
	-- @return status true on success, false on failure
	-- @return table containing a table of columns for each row
	--         or error message on failure
	Query = function( self, query )
	
		local queryPacket = QueryPacket:new()
		local status, result, data, token, colinfo, rows
		local pos = 1
			
		if ( nil == self.stream ) then
			return false, "Not connected to server"
		end
	
		queryPacket:SetQuery( query )		
		status, result = self.stream:Send( queryPacket:ToString() )
		if ( not(status) ) then
			return false, result
		end

		status, data = self.stream:Receive()
		if ( not(status) ) then
			return false, data
		end

		-- Iterate over tokens until we get to a rowtag
		while( pos < data:len() ) do
			local rowtag = select(2, bin.unpack("C", data, pos))
			
			if ( rowtag == TokenType.Row ) then
				break
			end
			
			pos, token = Token.ParseToken( data, pos )
			if ( -1 == pos ) then
				return false, token
			end
			if ( token.type == TokenType.ErrorMessage ) then
				return false, token.error
			elseif ( token.type == TokenType.TDS7Results ) then
				colinfo = token.colinfo
			end
		end


		rows = {}
	
		while(true) do
			local rowtag
			pos, rowtag = bin.unpack("C", data, pos )

			if ( rowtag ~= TokenType.Row ) then
				break
			end

			if ( rowtag == TokenType.Row and colinfo and #colinfo > 0 ) then
				local columns = {}
				
				for i=1, #colinfo do
					local val
				
					if ( ColumnData.Parse[colinfo[i].type] ) then
						pos, val = ColumnData.Parse[colinfo[i].type](data, pos)
						if ( -1 == pos ) then
							return false, val
						end
						table.insert(columns, val)
					else
						return false, ("unknown datatype=0x%X"):format(colinfo[i].type)
					end
				end
				table.insert(rows, columns)
			end
		end
		
		result = {}
		result.rows = rows
		result.colinfo = colinfo
		
		return true, result
	end,
		
}

--- "static" Utility class containing mostly conversion functions
Util = 
{
	--- Converts a string to a wide string
	--
	-- @param str string to be converted
	-- @return string containing a two byte representation of str where a zero
	--         byte character has been tagged on to each character.
	ToWideChar = function( str )
		return str:gsub("(.)", "%1" .. string.char(0x00) )
	end,
	
	
	--- Concerts a wide string to string
	--
	-- @param wstr containing the wide string to convert
	-- @return string with every other character removed
	FromWideChar = function( wstr )
		local str = ""
		if ( nil == wstr ) then
			return nil
		end
		for i=1, wstr:len(), 2 do
			str = str .. wstr:sub(i, i)
		end
		return str
	end,
	
	--- Takes a table as returned by Query and does some fancy formatting
	--  better suitable for <code>stdnse.output_result</code>
	--
	-- @param tbl as recieved by <code>Helper.Query</code>
	-- @param with_headers boolean true if output should contain column headers
	-- @return table suitable for <code>stdnse.output_result</code>
	FormatOutputTable = function ( tbl, with_headers )
		local new_tbl = {}
		local col_names = {}

		if ( not(tbl) ) then
			return
		end
		
		if ( with_headers and tbl.rows and #tbl.rows > 0 ) then
			local headers
			table.foreach( tbl.colinfo, function( k, v ) table.insert( col_names, v.text) end)
			headers = stdnse.strjoin("\t", col_names)
			table.insert( new_tbl, headers)
			headers = headers:gsub("[^%s]", "=")
			table.insert( new_tbl, headers )
		end
		
		for _, v in ipairs( tbl.rows ) do
			table.insert( new_tbl, stdnse.strjoin("\t", v) )
		end

		return new_tbl
	end,
	
	--- Decodes the version based on information from the SQL browser service.
	--
	-- @param info table with instance information as received by
	--        <code>Helper.Discover</code>
	-- @return status true on successm false on failure
	-- @return version table containing the following fields
	--         <code>product</code>, <code>version</code>,
	--         <code>level</code>
	DecodeBrowserInfoVersion = function(info)

		local VER_INFO = {
			["^6%.0"] = "6.0", ["^6%.5"] = "6.5", ["^7%.0"] = "7.0", 
			["^8%.0"] = "2000",	["^9%.0"] = "2005",	["^10%.0"]= "2008",
		}

		local VER_LEVEL = {
			["9.00.3042"] = "SP2", ["9.00.3043"] = "SP2", ["9.00.2047"] = "SP1",
			["9.00.1399"] = "RTM", ["10.0.1075"] = "CTP", ["10.0.1600"] = "CTP",
			["10.0.2531"] = "SP1"
		}

		local product = ""
		local version = {}

		for m, v in pairs(VER_INFO) do
			if ( info.version:match(m) ) then
				product=v
				break
			end
		end
		if ( info.name == "SQLEXPRESS" ) then
			product = product .. " Express Edition"
		end
		version.product = ("Microsoft SQL Server %s"):format(product)
		version.version = info.version
		for ver, level in pairs( VER_LEVEL ) do
			-- make sure we're comparing the same length
			local len = ( #info.version > #ver ) and #ver or #info.version
			if ( ver == info.version:sub(1, len) ) then
				version.level = level
				break
			end
		end
		if ( version.level ) then
			version.version = version.version .. (" (%s)"):format(version.level)
		end
		version.version = version.version .. " - UNVERIFIED"
		return true, version
	end
	
}
