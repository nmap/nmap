---
-- DB2 Library supporting a very limited subset of operations
--
-- Summary
-- -------
-- 	o The library currently provides functionality to:
--		1. Query the server for basic settings using the 
--		   <code>getServerInfo</code> function of the helper class
--		2. Authenticate to a DB2 server using a plain-text username and
--		   password.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--	 o DRDA
--		- Implements the Distributed Relational Database Architecture class 
--
--   o DRDAParameter
--		- Implements a number of functions to handle DRDA parameters
--
--   o DDM
-- 		- Implements the DDM portion of the DRDA structure
--
--	 o Command
--		- Provides functions for easy creation of the most common DRDA's
--		- Implemented as a static class that returns an instance of the DRDA
--
--   o Helper
--		- A helper class that provides easy access to the rest of the library
--
--	 o DB2Socket
--		- A smallish socket wrapper that provides fundamental buffering
--
--   o StringUtil
--		- Provides EBCDIC/ASCII conversion functions
--
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
--	db2helper 	= db2.Helper:new()
--	status, err = db2helper:connect(host, port)
--	status, res = db2helper:getServerInfo()
--	status, err = db2helper:close()
-- </code>
--
-- Additional information
-- ----------------------
-- The implementation is based on packet dumps and the excellent decoding
-- provided by Wireshark. 
--
-- There is some documentation over at:
-- 	o http://publib.boulder.ibm.com/infocenter/dzichelp/v2r2/topic/
-- com.ibm.db29.doc.drda/db2z_drda.htm [link spans two lines]
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

--
-- Version 0.1
-- Created 05/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

module(... or "db2", package.seeall)

require "bin"

-- CodePoint constants
CodePoint = {
	TYPDEFNAM	= 0x002f,
	TYPDEFOVR	= 0x0035,
	ACCSEC		= 0x106d,
	SECCHK		= 0x106e,
	EXCSAT 		= 0x1041,
	PRDID		= 0x112e,
	SRVCLSNM 	= 0x1147,
	SRVRLSLV 	= 0x115a,
	EXTNAM 		= 0x115e,
	SRVNAM 		= 0x116d,
	USRID		= 0x11a0,
	PASSWORD	= 0x11a1,
	SECMEC		= 0x11a2,
	SECCHKCD	= 0x11a4,
	MGRLVLLS 	= 0x1404,
	EXCSATRD	= 0x1443,
	ACCRDB		= 0x2001,
	PRDDATA		= 0x2104,
	RDBACCL		= 0x210f,
	RDBNAM		= 0x2110,
	RDBNFNRM	= 0x2211,
	RDBAFLRM	= 0x221a,
}

-- Security Mechanism
SecMec =
{
	USER_PASSWORD = 0x0003,
	USER_ONLY = 0x0004,
	CHANGE_PASSWORD = 0x0005,
	USER_PASS_SUBST	= 0x0006,
	USER_ENC_PASS = 0x0007,
	ENC_USER_ENC_PASS = 0x0009,
	ENC_CHANGE_PASS	= 0x000A,
	KERBEROS = 0x000B,
	ENC_USER_DATA = 0x000C,
	ENC_USER_ENC_PASS_ENC_DATA = 0x000D,
	ENC_USER_ENC_PASS_ENC_NEWPASS_ENC_DATA = 0x000E,
}

-- Distributed Relational Database Architecture (DRDA) Class
DRDA = {
	
	new = function(self, ddm)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.Parameters = {}
		o.DDM = ddm
		return o
	end,
	
	--- Sets the DDM 
	--
	-- @param ddm DDM to assign to the DRDA
	-- @return status boolean true on success, false on failure
	setDDM = function( self, ddm )
		if ( not(ddm) ) then
			return false, "DDM cannot be nil"
		end
		self.DDM = ddm
		return true
	end,
	
	--- Adds a DRDA parameter to the table
	--
	-- @param param DRDAParam containing the parameter to add to the table
	-- @return status bool true on success, false on failure
	-- @return err string containing the error message if status is false
	addParameter = function( self, param )
		if ( not(self.DDM) ) then
			stdnse.print_debug("db2.DRDA.addParameter: DDM must be set prior to adding parameters")
			return false, "DDM must be set prior to adding parameters"
		end
		if ( not(param) ) then
			stdnse.print_debug("db2.DRDA.addParameter: Param cannot be nil")
			return false, "Param cannot be nil"
		end
		
		table.insert(self.Parameters, param)
	
		-- update the DDM length fields
		self.DDM.Length = self.DDM.Length + param.Length
		self.DDM.Length2 = self.DDM.Length2 + param.Length
		
		return true
	end,
	
	--- Gets a parameter from the DRDA parameter table
	--
	-- @param codepoint number containing the parameter type ro retrieve
	-- @return param DRDAParameter containing the requested parameter
	getParameter = function( self, codepoint )
		for _, v in ipairs( self.Parameters ) do
			if ( v.CodePoint == codepoint ) then
				return v
			end
		end	
		return
	end,
	
	--- Converts the DRDA class to a string
	--
	-- @return data containing the object instance		
	toString = function(self)
		local data
		
		if ( not(self.DDM) ) then
			stdnse.print_debug("db2.DRDA.toString: DDM cannot be nil")
			return nil
		end
		
		data = bin.pack(">SCCSSS", self.DDM.Length, self.DDM.Magic, self.DDM.Format, self.DDM.CorelId, self.DDM.Length2, self.DDM.CodePoint )
		for k,v in ipairs(self.Parameters) do
			data = data .. v:toString()
		end
		return data
	end,
	
	--- Sends the DRDA over the db2socket
	--
	-- @param socket DB2Socket over which to send the data
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	send = function( self, db2socket )
		return db2socket:send( self:toString() )
	end,
	
	--- Receives data from the db2socket and builds a DRDA object
	--
	-- @param db2socket from which to read data
	-- @return Status (true or false).
	-- @return Data (if status is true) or error string (if status is false).	
	receive = function( self, db2socket )
		local DDM_SIZE = 10
		local status, data, ddm, param
		local pos = 1
		
		-- first read atleast enough so that we can populate the DDM
		status, data = db2socket:recv( DDM_SIZE )
		if ( not(status) ) then
			stdnse.print_debug("db2.DRDA.receive: %s", data)
			return false, ("Failed to read at least %d bytes from socket"):format(DDM_SIZE)
		end
		
		ddm = DDM:new()
		ddm:fromString( data )
		self:setDDM( ddm )
		
		status, data = db2socket:recv( ddm.Length - 10 )
		if ( not(status) ) then
			return false, ("Failed to read the remaining %d bytes of the DRDA message")
		end

		-- add parameters until pos reaches the "end"
		repeat
			param = DRDAParameter:new()
			pos = param:fromString( data, pos )
			self:addParameter( param )
		until ( #data <= pos )
			
		return true
	end,

}

-- The DRDAParameter class implements the DRDA parameters
DRDAParameter = {
		
	--- DRDA Parameter constructor
	--
	-- @param codepoint number containing the codepoint value
	-- @param data string containing the data portion of the DRDA parameter
	-- @return o DRDAParameter object 
	new = function(self, codepoint, data)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.CodePoint = codepoint
		if ( data ) then
			o.Data = data
			o.Length = #o.Data + 4
		else
			o.Length = 4
		end
		return o
	end,

	--- Converts the DRDA Parameter object to a string
	--
	-- @return data string containing the DRDA Parameter
	toString = function( self )
		local data = bin.pack(">SS", self.Length, self.CodePoint )
		
		if ( self.Data ) then
			data = data .. bin.pack("A", self.Data)
		end
		return data
	end,
	
	--- Builds a DRDA Parameter from a string
	--
	-- @param data string from which to build the DRDA Parameter
	-- @param pos number containing the offset into data
	-- @return pos the new position after processing, -1 on error
	fromString = function( self, data, pos )
		if( #data < 4 ) then
			return -1
		end
		pos, self.Length, self.CodePoint = bin.unpack( ">SS", data, pos )

		-- make sure the Length is assigned a value even though 0(nil) is returned
		self.Length = self.Length or 0

		if ( self.Length > 0 ) then
			pos, self.Data = bin.unpack("A" .. self.Length - 4, data, pos )
		end
		return pos
	end,
	
	--- Returns the data portion of the parameter as an ASCII string
	--
	-- @return str containing the data portion of the DRDA parameter as ASCII
	getDataAsASCII = function( self )
		return StringUtil.toASCII( self.Data )
	end,
	
	--- Returns the data in EBCDIC format
	--
	-- @return str containing the data portion of the DRDA parameter in EBCDIC
	getData = function( self )
		return self.Data
	end,

}

-- Distributed data management (DDM)
DDM = {
	
	Formats =
	{
		RESERVED 		 = 0x80,
		CHAINED  		 = 0x40,
		CONTINUE 		 = 0x20,
		SAME_CORRELATION = 0x10,
	},
	
	Length = 10,
	Magic = 0xD0,
	Format = 0x41,
	CorelId = 1,
	Length2 = 4,
	CodePoint = 0,

	--- Creates a new DDM packet
	--
	-- @param codepoint
	-- @param format
	-- @param corelid
	-- @return DDM object
	new = function(self, codepoint, format, corelid)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.CodePoint = codepoint
		if ( format ) then
			o.Format = format
		end
		if ( corelid ) then
			o.CorelId = corelid
		end
		return o
	end,

	--- Converts the DDM object to a string
	toString = function( self )
		return bin.pack(">SCCSSS", self.Length, self.Magic, self.Format, self.CorelId, self.Length2, self.CodePoint)
	end,
	
	--- Constructs a DDM object from a string
	--
	-- @param str containing the data from which to construct the object
	fromString = function( self, str )
		local DDM_SIZE = 10
		local pos = 1
		
		if ( #str < DDM_SIZE ) then
			return -1, ("db2.DDM.fromString: str was less than DDM_SIZE (%d)"):format( DDM_SIZE )
		end
		
		pos, self.Length, self.Magic, self.Format, self.CorelId, self.Length2, self.CodePoint = bin.unpack( ">SCCSSS", str )
		return pos
	end,
	
	--- Verifiers if there are additional DRDA's following
	--
	-- @return true if the DRDA is to be chained, false if it's the last one	
	isChained = function( self )
		if ( bit.band( self.Format, DDM.Formats.CHAINED ) == DDM.Formats.CHAINED ) then
			return true
		end
		return false
	end,
	
	--- Set the DRDA as chained (more following)
	--
	-- @param chained boolean true if more DRDA's are following
	setChained = function( self, chained )
		if ( self:isChained() ) then
			self.Format = bit.bxor( self.Format, self.Formats.CHAINED )
		else
			self.Format = bit.bor( self.Format, self.Formats.CHAINED )
		end
	end,
	
}

-- static DRDA packet construction class
Command = 
{
	--- Builds an EXCSAT DRDA packet
	--
	-- @param extname string containing the external name
	-- @param srvname string containing the server name
	-- @param rellev string containing the server product release level
	-- @param mgrlvlls string containing the manager level list
	-- @param srvclass string containing the server class name
	-- @return drda DRDA instance
	EXCSAT = function( extname, srvname, rellev, mgrlvlls, srvclass )
		local drda = DRDA:new( DDM:new( CodePoint.EXCSAT ) )
	
		drda:addParameter( DRDAParameter:new( CodePoint.EXTNAM, StringUtil.toEBCDIC( extname ) ) )
		drda:addParameter( DRDAParameter:new( CodePoint.SRVNAM, StringUtil.toEBCDIC( srvname ) ) )
		drda:addParameter( DRDAParameter:new( CodePoint.SRVRLSLV, StringUtil.toEBCDIC( rellev ) ) )
		drda:addParameter( DRDAParameter:new( CodePoint.MGRLVLLS, mgrlvlls ) )
		drda:addParameter( DRDAParameter:new( CodePoint.SRVCLSNM, StringUtil.toEBCDIC( srvclass ) ) )

		return drda
	end,
	
	--- Builds an ACCSEC DRDA packet
	--
	-- @param secmec number containing the security mechanism ID
	-- @param database string containing the database name
	-- @return drda DRDA instance
	ACCSEC = function( secmec, database )
		local drda = DRDA:new( DDM:new( CodePoint.ACCSEC ) )
		drda:addParameter( DRDAParameter:new( CodePoint.SECMEC, secmec ))
		drda:addParameter( DRDAParameter:new( CodePoint.RDBNAM, StringUtil.toEBCDIC(StringUtil.padWithChar(database,' ', 18)) ))
	
		return drda
	end,

	--- Builds a SECCHK DRDA packet
	--
	-- @param secmec number containing the security mechanism ID
	-- @param database string containing the database name
	-- @param username string
	-- @param password string
	-- @return drda DRDA instance	
	SECCHK = function( secmec, database, username, password )
		local drda = DRDA:new( DDM:new( CodePoint.SECCHK ) )
		drda:addParameter( DRDAParameter:new( CodePoint.SECMEC, secmec ))
		drda:addParameter( DRDAParameter:new( CodePoint.RDBNAM, StringUtil.toEBCDIC(StringUtil.padWithChar(database,' ', 18)) ))
		drda:addParameter( DRDAParameter:new( CodePoint.USRID, StringUtil.toEBCDIC(username) ) )
		drda:addParameter( DRDAParameter:new( CodePoint.PASSWORD, StringUtil.toEBCDIC(password) ) )
		
		return drda
	end,
	
	--- Builds an ACCRDB DRDA packet
	--
	-- @param database string containing the database name
	-- @param rdbaccl string containing the RDB access manager class
	-- @param prdid string containing the product id
	-- @param typdefnam string containing the data type definition name
	-- @param typdefovr string containing the data type definition override
	-- @return drda DRDA instance		
	ACCRDB = function( database, rdbaccl, prdid, prddata, typdefnam, typdefovr )
		local drda = DRDA:new( DDM:new( CodePoint.ACCRDB ) )
		drda:addParameter( DRDAParameter:new( CodePoint.RDBNAM, StringUtil.toEBCDIC(StringUtil.padWithChar(database,' ', 18)) ) )

		if ( rdbaccl ) then
			drda:addParameter( DRDAParameter:new( CodePoint.RDBACCL, rdbaccl ) )
		end
		if ( prdid ) then
			drda:addParameter( DRDAParameter:new( CodePoint.PRDID, StringUtil.toEBCDIC( prdid ) ) )
		end
		if ( prddata ) then
			drda:addParameter( DRDAParameter:new( CodePoint.PRDDATA, StringUtil.toEBCDIC( prddata ) ) )
		end
		if( typdefnam ) then
			drda:addParameter( DRDAParameter:new( CodePoint.TYPDEFNAM, StringUtil.toEBCDIC( typdefnam ) ) )
		end
		if( typdefovr ) then
			drda:addParameter( DRDAParameter:new( CodePoint.TYPDEFOVR, typdefovr ) )
		end
		
		return drda
	end
	
}


-- Helper Class
Helper = {

	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	--- Connect to the DB2 host
	--
	-- @param host table
	-- @param port table
	-- @return Status (true or false).
	-- @return Error code (if status is false).	
	connect = function( self, host, port )
		self.db2socket = DB2Socket:new()
		return self.db2socket:connect(host.ip, port.number, port.protocol)
	end,

	--- Closes an open connection.
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).	
	close = function( self )
		self.db2socket:close()
	end,
	
	--- Returns Server Information (name, platform, version)
	--
	-- @return table containing <code>extname</code>, <code>srvclass</code>, 
	--				<code>srvname</code> and <code>prodrel</code>
	getServerInfo = function( self )
		local mgrlvlls = bin.pack("H", "1403000724070008240f00081440000814740008")
		local drda_excsat = Command.EXCSAT( "", "", "", mgrlvlls, "" )
		local drda, response, param, status, err
	
		status, err = self.db2socket:sendDRDA( { drda_excsat } )
		if ( not(status) ) then
			return false, err
		end
		
		status, drda = self.db2socket:recvDRDA()
		if( not(status) ) then
			return false, drda
		end
	
		if ( #drda > 0 and drda[1].DDM.CodePoint == CodePoint.EXCSATRD ) then
			response = {}
			param = drda[1]:getParameter( CodePoint.EXTNAM )
			if ( param ) then
				response.extname = param:getDataAsASCII()
			end
			param = drda[1]:getParameter( CodePoint.SRVCLSNM )
			if ( param ) then
				response.srvclass = param:getDataAsASCII()
			end
			param = drda[1]:getParameter( CodePoint.SRVNAM )
			if ( param ) then
				response.srvname = param:getDataAsASCII()
			end
			param = drda[1]:getParameter( CodePoint.SRVRLSLV )
			if ( param ) then
				response.prodrel = param:getDataAsASCII()
			end
		else
			return false, "The response contained no EXCSATRD"	
		end
		
		return true, response	
	end,
	
	--- Login to DB2 database server
	--
	-- @param database containing the name of the database
	-- @param username containing the authentication username
	-- @param password containing the authentication password
	-- @return Status (true or false)
	-- @return err message (if status if false)
	login = function( self, database, username, password )
		local drda = {}
		local data, param, status, err, _
		
		local mgrlvlls = bin.pack("H", "1403000724070008240f00081440000814740008")
		local secmec, prdid = "\00\03", "JCC03010"
		
		local drda_excsat = Command.EXCSAT( "", "", "", mgrlvlls, "" )
		local drda_accsec = Command.ACCSEC( secmec, database )
		local drda_secchk = Command.SECCHK( secmec, database, username, password )
		local drda_accrdb = Command.ACCRDB( database )
		
		status, err = self.db2socket:sendDRDA( { drda_excsat, drda_accsec } )
		if ( not(status) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: DB2Socket error: %s", err )
			return false, ("ERROR: DB2Socket error: %s"):format( err )
		end
		
		status, drda = self.db2socket:recvDRDA()
		if( not(status) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: DB2Socket error: %s", drda )
			return false, ("ERROR: DB2Socket error: %s"):format( drda )
		end
		
		if ( 2 > #drda ) then
			stdnse.print_debug("db2.Helper.login: db2.Helper.login: ERROR: Expected two DRDA records")
			return false, "ERROR: Expected two DRDA records"
		end
		
		-- Check if the DB is accessible
		for i=1, #drda do
			if ( drda[i].DDM.CodePoint == CodePoint.RDBNFNRM or
			 	drda[i].DDM.CodePoint == CodePoint.RDBAFLRM ) then
				stdnse.print_debug("db2.Helper.login: ERROR: RDB not found")
				return false, "ERROR: Database not found"
			end
		end
		
		param = drda[2]:getParameter( CodePoint.SECMEC )
		if ( not(param) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: Response did not contain any valid security mechanisms")
			return false, "ERROR: Response did not contain any valid security mechanisms"
		end
		
		if ( select(2, bin.unpack(">S", param:getData())) ~= SecMec.USER_PASSWORD ) then
			stdnse.print_debug("db2.Helper.login: ERROR: Securite Mechanism not supported")
			return false, "ERROR: Security mechanism not supported"
		end
		
		status, err = self.db2socket:sendDRDA( { drda_secchk, drda_accrdb } )	
		if ( not(status) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: DB2Socket error: %s", err )
			return false, ("ERROR: DB2Socket error: %s"):format( err )
		end
	
		status, drda = self.db2socket:recvDRDA()
		if( not(status) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: DB2Socket error: %s", drda )
			return false, ("ERROR: DB2Socket error: %s"):format( drda )
		end
		
		param = drda[1]:getParameter( CodePoint.SECCHKCD )
		if ( not(param) ) then
			stdnse.print_debug("db2.Helper.login: ERROR: Authentication failed")
			return false, "ERROR: Authentication failed"
		end
		
		local secchkcd = select( 2, bin.unpack( "C", param:getData() ) )
		if ( 0 ~= secchkcd ) then
			stdnse.print_debug( "db2.Helper.login: ERROR: Authentication failed, error code: %d", secchkcd )
			return false, ("ERROR: Authentication failed, error code: %d"):format(secchkcd)
		end
				
		return true
	end,
	
}

-- The DB2Socket class
--
-- Allows for reading an exact count of bytes opposed to the nmap socket
-- implementation that does at least count of bytes.
--
-- The DB2Socket makes use of nmaps underlying socket implementation and
-- buffers the bytes exceeding the number asked for. The next call to the
-- <code>recv</code> function will fetch bytes from the buffer and call
-- the <code>recieve_bytes</code> function of the underlying when there
-- are no more buffered bytes.
--
-- The <code>connect</code>, <code>close</code> and <code>send</code>
-- functions are wrappers around the same functions of the nmap socket code.
-- Consult the nsedoc for additional information on these.
DB2Socket = {
	
	retries = 3,
	
	new = function(self)
		local o = {}
       	setmetatable(o, self)
        self.__index = self
		o.Socket = nmap.new_socket()
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
	
	--- Sends a single or multiple DRDA's over the socket
	--
	-- @param drda a single or a table containing multiple DRDA's
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	sendDRDA = function( self, drda )
		local data = ""
				
		if ( 0 == #drda ) then
			data = drda:toString()
		else
			-- do some DDM fixup in here
			for i=1, #drda do
				if ( i == 1 and #drda > 1 ) then
					drda[1].DDM.Format = 0x41
				else
					drda[i].DDM.Format = 0x01
				end
				drda[i].DDM.CorelId = i
				data = data .. drda[i]:toString()
			end
		end
		
		return self:send(data)
	end,
	
	--- Reads a single or multiple DRDA's of the socket
	--
	-- @return status (true or false)
	-- @return drda table containing retrieved DRDA's
	recvDRDA = function( self )
		local status, err
		local drda_tbl = {}
		
		repeat
			local drda = DRDA:new()
			status, err = drda:receive( self )
			if ( not(status) ) then
				return false, err
			end
			table.insert(drda_tbl, drda)
		until ( not(drda.DDM:isChained()) )
			
		return true, drda_tbl
	end,
}

-- EBCDIC/ASCII Conversion tables
a2e_hex = 			 "00010203372D2E2F1605250B0C0D0E0F101112133C3D322618193F271C1D1E1F"
a2e_hex = a2e_hex .. "405A7F7B5B6C507D4D5D5C4E6B604B61F0F1F2F3F4F5F6F7F8F97A5E4C7E6E6F"
a2e_hex = a2e_hex .. "7CC1C2C3C4C5C6C7C8C9D1D2D3D4D5D6D7D8D9E2E3E4E5E6E7E8E9ADE0BD5F6D"
a2e_hex = a2e_hex .. "79818283848586878889919293949596979899A2A3A4A5A6A7A8A9C04FD0A107"
a2e_hex = a2e_hex .. "202122232415061728292A2B2C090A1B30311A333435360838393A3B04143EE1"
a2e_hex = a2e_hex .. "4142434445464748495152535455565758596263646566676869707172737475"
a2e_hex = a2e_hex .. "767778808A8B8C8D8E8F909A9B9C9D9E9FA0AAABAC4AAEAFB0B1B2B3B4B5B6B7"
a2e_hex = a2e_hex .. "B8B9BABBBC6ABEBFCACBCCCDCECFDADBDCDDDEDFEAEBECEDEEEFFAFBFCFDFEFF"

e2a_hex =			 "000102039C09867F978D8E0B0C0D0E0F101112139D8508871819928F1C1D1E1F"
e2a_hex = e2a_hex .. "80818283840A171B88898A8B8C050607909116939495960498999A9B14159E1A"
e2a_hex = e2a_hex .. "20A0A1A2A3A4A5A6A7A8D52E3C282B7C26A9AAABACADAEAFB0B121242A293B5E"
e2a_hex = e2a_hex .. "2D2FB2B3B4B5B6B7B8B9E52C255F3E3FBABBBCBDBEBFC0C1C2603A2340273D22"
e2a_hex = e2a_hex .. "C3616263646566676869C4C5C6C7C8C9CA6A6B6C6D6E6F707172CBCCCDCECFD0"
e2a_hex = e2a_hex .. "D17E737475767778797AD2D3D45BD6D7D8D9DADBDCDDDEDFE0E1E2E3E45DE6E7"
e2a_hex = e2a_hex .. "7B414243444546474849E8E9EAEBECED7D4A4B4C4D4E4F505152EEEFF0F1F2F3"
e2a_hex = e2a_hex .. "5C9F535455565758595AF4F5F6F7F8F930313233343536373839FAFBFCFDFEFF"

-- Creates the lookup tables needed for conversion
a2e_tbl = bin.pack("H", a2e_hex)
e2a_tbl = bin.pack("H", e2a_hex)

-- Handle EBCDIC/ASCII conversion
StringUtil =
{
	--- Converts an ASCII string to EBCDIC
	--
	-- @param ascii string containing the ASCII value
	-- @return string containing the EBCDIC value
	toEBCDIC = function( ascii )
		local val, ret = 0, ""

		for i=1, #ascii do
			val = ascii.byte(ascii,i) + 1
			ret = ret .. a2e_tbl:sub(val, val)
		end
		return ret
	end,

	--- Converts an EBCDIC string to ASCII
	--
	-- @param ebcdic string containing EBCDIC value
	-- @return string containing ASCII value
	toASCII = function( ebcdic )
		local val, ret = 0, ""
		
		for i=1, #ebcdic do
			val = ebcdic.byte(ebcdic,i) + 1
			ret = ret .. e2a_tbl:sub(val, val)
		end
		return ret
	end,

	--- Pads a string with a character
	--
	-- @param str string to pad
	-- @param chr char to pad with
	-- @len the total length of the finnished string
	-- @return str string containing the padded string
	padWithChar = function( str, chr, len )
		if ( len < #str ) then
			return str
		end
		for i=1, (len - #str) do
			str = str .. chr
		end
		return str
	end,
}
