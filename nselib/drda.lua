---
-- DRDA Library supporting a very limited subset of operations.
--
-- Summary
-- * The library currently provides functionality to: (1) Query the server for
-- basic settings using the <code>getServerInfo</code> function of the helper
-- class. (2) Authenticate to a DB2 server using a plain-text username and
-- password.
--
-- The library contains the following classes:
-- * <code>DRDA</code>
-- ** Implements the Distributed Relational Database Architecture class .
-- * <code>DRDAParameter</code>
-- ** Implements a number of functions to handle DRDA parameters.
-- * <code>DDM</code>
-- ** Implements the DDM portion of the DRDA structure
-- * <code>Command</code>
-- ** Provides functions for easy creation of the most common DRDAs.
-- ** Implemented as a static class that returns an instance of the DRDA.
-- * <code>Helper</code>
-- ** A helper class that provides easy access to the rest of the library
-- * <code>DB2Socket</code>
-- ** A smallish socket wrapper that provides fundamental buffering
-- * <code>StringUtil</code>
-- ** Provides EBCDIC/ASCII conversion functions
-- * <code>Comm</code>
-- ** Provides fundamental communication support (send/receive DRDAPacket)
-- * <code>DRDAPacket</code>
-- ** A class holding one or more DRDA's and provides some basic access methods
--
-- The following sample code illustrates how scripts can use the Helper class
-- to interface with the library:
--
-- <code>
-- db2helper = drda.Helper:new()
-- status, err = db2helper:connect(host, port)
-- status, res = db2helper:getServerInfo()
-- status, err = db2helper:close()
-- </code>
--
-- The implementation is based on packet dumps and the excellent decoding
-- provided by Wireshark.
--
-- There is some documentation at
-- http://publib.boulder.ibm.com/infocenter/dzichelp/v2r2/topic/com.ibm.db29.doc.drda/db2z_drda.htm.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>
--

--
-- Version 0.2
-- Created 05/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/27/2010 - v0.2 - Added the comm class and made a few improvements
--                             to sending and receiving packets. Changed the
--                             helper login method to support:
--                             x IBM DB2
--                             x Apache Derby
--                             x IBM Informix Dynamic Server

local bin = require "bin"
local bit = require "bit"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("drda", stdnse.seeall)

-- CodePoint constants
CodePoint = {
  CODEPNT   = 0x000c,
  TYPDEFNAM = 0x002f,
  TYPDEFOVR = 0x0035,
  ACCSEC    = 0x106d,
  SECCHK    = 0x106e,
  EXCSAT    = 0x1041,
  PRDID     = 0x112e,
  SRVCLSNM  = 0x1147,
  SVRCOD    = 0x1149,
  SYNERRCD  = 0x114a,
  SRVRLSLV  = 0x115a,
  EXTNAM    = 0x115e,
  SRVNAM    = 0x116d,
  USRID     = 0x11a0,
  PASSWORD  = 0x11a1,
  SECMEC    = 0x11a2,
  SECCHKCD  = 0x11a4,
  SECCHKRM  = 0x1219,
  SYNTAXRM  = 0x124c,
  MGRLVLLS  = 0x1404,
  EXCSATRD  = 0x1443,
  ACCSECRD  = 0x14ac,
  ACCRDB    = 0x2001,
  PRDDATA   = 0x2104,
  RDBACCL   = 0x210f,
  RDBNAM    = 0x2110,
  CRRTKN    = 0x2135,
  ACCRDBRM  = 0x2201,
  RDBNFNRM  = 0x2211,
  RDBAFLRM  = 0x221a,
  RDBATHRM  = 0x22cb,
}

-- Security Mechanism
SecMec =
{
  USER_PASSWORD = 0x0003,
  USER_ONLY = 0x0004,
  CHANGE_PASSWORD = 0x0005,
  USER_PASS_SUBST = 0x0006,
  USER_ENC_PASS = 0x0007,
  ENC_USER_ENC_PASS = 0x0009,
  ENC_CHANGE_PASS = 0x000A,
  KERBEROS = 0x000B,
  ENC_USER_DATA = 0x000C,
  ENC_USER_ENC_PASS_ENC_DATA = 0x000D,
  ENC_USER_ENC_PASS_ENC_NEWPASS_ENC_DATA = 0x000E,
}

DRDAPacket = {

  new = function(self, drda_array)
    local o = {
      drda_array = drda_array,
      count = #drda_array
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  getDRDAByCodePoint = function( self, codepoint )
    for i=1, #self.drda_array do
      if ( self.drda_array[i].DDM.CodePoint == codepoint ) then
        return self.drda_array[i]
      end
    end
  end,

  getDRDA = function( self, n )
    return ( #self.drda_array >= n ) and self.drda_array[n] or nil
  end,

  __tostring = function( self )
    local data = ""
    -- do some DDM fixup in here
    for i=1, #self.drda_array do
      if ( i == 1 and #self.drda_array > 1 ) then
        self.drda_array[1].DDM.Format = 0x41
      else
        self.drda_array[i].DDM.Format = 0x01
      end
      self.drda_array[i].DDM.CorelId = i
      data = data .. tostring(self.drda_array[i])
    end
    return data
  end

}

-- Distributed Relational Database Architecture (DRDA) Class
DRDA = {

  new = function(self, ddm)
    local o = {
      Parameters = {},
      DDM = ddm
    }
    setmetatable(o, self)
    self.__index = self
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
      stdnse.debug1("drda.DRDA.addParameter: DDM must be set prior to adding parameters")
      return false, "DDM must be set prior to adding parameters"
    end
    if ( not(param) ) then
      stdnse.debug1("drda.DRDA.addParameter: Param cannot be nil")
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
  __tostring = function(self)
    if ( not(self.DDM) ) then
      stdnse.debug1("drda.DRDA.toString: DDM cannot be nil")
      return nil
    end

    local data = bin.pack(">SCCSSS", self.DDM.Length, self.DDM.Magic, self.DDM.Format, self.DDM.CorelId, self.DDM.Length2, self.DDM.CodePoint )
    for k,v in ipairs(self.Parameters) do
      data = data .. tostring(v)
    end
    return data
  end,

  --- Sends the DRDA over the db2socket
  --
  -- @param db2socket DB2Socket over which to send the data
  -- @return Status (true or false).
  -- @return Error code (if status is false).
  send = function( self, db2socket )
    return db2socket:send( tostring(self) )
  end,

  --- Receives data from the db2socket and builds a DRDA object
  --
  -- @param db2socket from which to read data
  -- @return Status (true or false).
  -- @return Data (if status is true) or error string (if status is false).
  receive = function( self, db2socket )
    local DDM_SIZE = 10
    local pos = 1

    -- first read atleast enough so that we can populate the DDM
    local status, data = db2socket:receive_buf( match.numbytes(DDM_SIZE), true )
    if ( not(status) ) then
      stdnse.debug1("drda.DRDA.receive: %s", data)
      return false, ("Failed to read at least %d bytes from socket"):format(DDM_SIZE)
    end

    local ddm = DDM:new()
    ddm:fromString( data )
    self:setDDM( ddm )

    status, data = db2socket:receive_buf( match.numbytes(ddm.Length - 10), true )
    if ( not(status) ) then
      return false, ("Failed to read the remaining %d bytes of the DRDA message")
    end

    -- add parameters until pos reaches the "end"
    repeat
      local param = DRDAParameter:new()
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
    local o = {
      CodePoint = codepoint,
      Data = data,
      Length = ( data and #data + 4 or 4 )
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts the DRDA Parameter object to a string
  --
  -- @return data string containing the DRDA Parameter
  __tostring = function( self )
    return bin.pack(">SSA", self.Length, self.CodePoint, self.Data or "" )
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
    RESERVED = 0x80,
    CHAINED = 0x40,
    CONTINUE = 0x20,
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
    local o = {
      CodePoint = codepoint,
      Format = format,
      CorelId = corelid
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts the DDM object to a string
  __tostring = function( self )
    return bin.pack(">SCCSSS", self.Length, self.Magic, self.Format, self.CorelId, self.Length2, self.CodePoint)
  end,

  --- Constructs a DDM object from a string
  --
  -- @param str containing the data from which to construct the object
  fromString = function( self, str )
    local DDM_SIZE = 10
    local pos = 1

    if ( #str < DDM_SIZE ) then
      return -1, ("drda.DDM.fromString: str was less than DDM_SIZE (%d)"):format( DDM_SIZE )
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
  ACCRDB = function( database, rdbaccl, prdid, prddata, typdefnam, crrtkn, typdefovr )
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
    if( crrtkn ) then
      drda:addParameter( DRDAParameter:new( CodePoint.CRRTKN, crrtkn ) )
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
    self.comm = Comm:new( host, port )
    return self.comm:connect()
  end,

  --- Closes an open connection.
  --
  -- @return Status (true or false).
  -- @return Error code (if status is false).
  close = function( self )
    self.comm:close()
  end,

  --- Returns Server Information (name, platform, version)
  --
  -- @return table containing <code>extname</code>, <code>srvclass</code>,
  --         <code>srvname</code> and <code>prodrel</code>
  getServerInfo = function( self )
    local mgrlvlls = bin.pack("H", "1403000724070008240f00081440000814740008")
    local drda_excsat = Command.EXCSAT( "", "", "", mgrlvlls, "" )
    local response, param, err

    local status, packet = self.comm:exchDRDAPacket( DRDAPacket:new( { drda_excsat } ) )
    if ( not(status) ) then return false, err end

    local drda = packet:getDRDAByCodePoint( CodePoint.EXCSATRD )
    if ( drda ) then
      response = {}
      param = drda:getParameter( CodePoint.EXTNAM )
      if ( param ) then
        response.extname = param:getDataAsASCII()
      end
      param = drda:getParameter( CodePoint.SRVCLSNM )
      if ( param ) then
        response.srvclass = param:getDataAsASCII()
      end
      param = drda:getParameter( CodePoint.SRVNAM )
      if ( param ) then
        response.srvname = param:getDataAsASCII()
      end
      param = drda:getParameter( CodePoint.SRVRLSLV )
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
    local mgrlvlls = bin.pack("H", "1403000724070008240f00081440000814740008")
    local secmec, prdid = "\00\03", "JCC03010"
    local tdovr = bin.pack("H", "0006119c04b80006119d04b00006119e04b8")
    local crrtkn= bin.pack("H", "d5c6f0f0f0f0f0f14bc3c6f4c4012a11168414")

    local drda_excsat = Command.EXCSAT( "", "", "", mgrlvlls, "" )
    local drda_accsec = Command.ACCSEC( secmec, database )
    local drda_secchk = Command.SECCHK( secmec, database, username, password )
    local drda_accrdb = Command.ACCRDB( database, "\x24\x07", "DNC10060", nil, "QTDSQLASC",  crrtkn, tdovr)

    local status, packet = self.comm:exchDRDAPacket( DRDAPacket:new( { drda_excsat, drda_accsec } ) )
    if( not(status) ) then return false, packet end

    if ( packet:getDRDAByCodePoint( CodePoint.RDBNFNRM ) or
        packet:getDRDAByCodePoint( CodePoint.RDBAFLRM ) ) then
      stdnse.debug1("drda.Helper.login: ERROR: RDB not found")
      return false, "ERROR: Database not found"
    end

    local drda = packet:getDRDAByCodePoint( CodePoint.ACCSECRD )
    if ( not(drda) ) then
      return false, "ERROR: Response did not contain any valid security mechanisms"
    end

    local param = drda:getParameter( CodePoint.SECMEC )
    if ( not(param) ) then
      stdnse.debug1("drda.Helper.login: ERROR: Response did not contain any valid security mechanisms")
      return false, "ERROR: Response did not contain any valid security mechanisms"
    end

    if ( select(2, bin.unpack(">S", param:getData())) ~= SecMec.USER_PASSWORD ) then
      stdnse.debug1("drda.Helper.login: ERROR: Securite Mechanism not supported")
      return false, "ERROR: Security mechanism not supported"
    end

    status, packet = self.comm:exchDRDAPacket( DRDAPacket:new( { drda_secchk, drda_accrdb } ) )
    if( not(status) ) then return false, "ERROR: Login failed" end

    --
    -- At this point we have a few differences in behaviour
    --  * DB2 has told us earlier if the DB does not exist
    --  * Apache Derby will do so here, regardless of the login was
    --    successful or not
    --  * Informix will tell us that the DB does not exist IF the
    --    login was successful
    --
    -- Therefore the order of these checks are important!!
    if ( packet:getDRDAByCodePoint( CodePoint.ACCRDBRM ) ) then
      return true
    -- Apache Derby responds differently with usernames containing spaces
    elseif ( packet:getDRDAByCodePoint( CodePoint.RDBATHRM ) ) then
      return false, "ERROR: Login failed"
    -- Informix responds with a SECCHKRM DDM response
    elseif ( packet:getDRDAByCodePoint( CodePoint.SECCHKRM ) ) then
      drda = packet:getDRDAByCodePoint( CodePoint.SECCHKRM )
      param= drda:getParameter( CodePoint.SECCHKCD )
      if ( param and param:getData() == "\0" ) then
        return true
      end
    elseif ( packet:getDRDAByCodePoint( CodePoint.RDBNFNRM ) or
      packet:getDRDAByCodePoint( CodePoint.RDBAFLRM ) ) then
      return false, "ERROR: Database not found"
    end
    return false, "ERROR: Login failed"
  end,

}

-- The communication class
Comm = {

  new = function(self, host, port)
    local o = {
      host = host,
      port = port,
      socket = nmap.new_socket()
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    return self.socket:connect(self.host, self.port)
  end,

  close = function(self)
    return self.socket:close()
  end,

  recvDRDA = function( self )
    local drda_tbl = {}

    repeat
      local drda = DRDA:new()
      local status, err = drda:receive( self.socket )
      if ( not(status) ) then
        return false, err
      end
      table.insert(drda_tbl, drda)
    until ( not(drda.DDM:isChained()) )
    return true, drda_tbl
  end,

  --- Sends a packet to the server and receives the response
  --
  -- @param DRDAPacket
  -- @return status true on success, false on failure
  -- @return packet an instance of DRDAPacket
  exchDRDAPacket = function( self, packet )
    local drda, err
    local status, err = self.socket:send( tostring(packet) )

    if ( not(status) ) then
      stdnse.debug1("drda.Helper.login: ERROR: DB2Socket error: %s", err )
      return false, ("ERROR: DB2Socket error: %s"):format( err )
    end

    status, drda = self:recvDRDA()
    if( not(status) ) then
      stdnse.debug1("drda.Helper.login: ERROR: DB2Socket error: %s", drda )
      return false, ("ERROR: DB2Socket error: %s"):format( drda )
    end
    return true, DRDAPacket:new( drda )
  end

}

-- EBCDIC/ASCII Conversion tables
a2e_hex = "00010203372D2E2F1605250B0C0D0E0F101112133C3D322618193F271C1D1E1F\z
405A7F7B5B6C507D4D5D5C4E6B604B61F0F1F2F3F4F5F6F7F8F97A5E4C7E6E6F\z
7CC1C2C3C4C5C6C7C8C9D1D2D3D4D5D6D7D8D9E2E3E4E5E6E7E8E9ADE0BD5F6D\z
79818283848586878889919293949596979899A2A3A4A5A6A7A8A9C04FD0A107\z
202122232415061728292A2B2C090A1B30311A333435360838393A3B04143EE1\z
4142434445464748495152535455565758596263646566676869707172737475\z
767778808A8B8C8D8E8F909A9B9C9D9E9FA0AAABAC4AAEAFB0B1B2B3B4B5B6B7\z
B8B9BABBBC6ABEBFCACBCCCDCECFDADBDCDDDEDFEAEBECEDEEEFFAFBFCFDFEFF"

e2a_hex = "000102039C09867F978D8E0B0C0D0E0F101112139D8508871819928F1C1D1E1F\z
80818283840A171B88898A8B8C050607909116939495960498999A9B14159E1A\z
20A0A1A2A3A4A5A6A7A8D52E3C282B7C26A9AAABACADAEAFB0B121242A293B5E\z
2D2FB2B3B4B5B6B7B8B9E52C255F3E3FBABBBCBDBEBFC0C1C2603A2340273D22\z
C3616263646566676869C4C5C6C7C8C9CA6A6B6C6D6E6F707172CBCCCDCECFD0\z
D17E737475767778797AD2D3D45BD6D7D8D9DADBDCDDDEDFE0E1E2E3E45DE6E7\z
7B414243444546474849E8E9EAEBECED7D4A4B4C4D4E4F505152EEEFF0F1F2F3\z
5C9F535455565758595AF4F5F6F7F8F930313233343536373839FAFBFCFDFEFF"

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
    return string.gsub(ascii, ".", function(a)
        local val = a:byte() + 1
        return a2e_tbl:sub(val, val)
      end)
  end,

  --- Converts an EBCDIC string to ASCII
  --
  -- @param ebcdic string containing EBCDIC value
  -- @return string containing ASCII value
  toASCII = function( ebcdic )
    return string.gsub(ebcdic, ".", function(e)
        local val = e:byte() + 1
        return e2a_tbl:sub(val, val)
      end)
  end,

  --- Pads a string with a character
  --
  -- @param str string to pad
  -- @param chr char to pad with
  -- @param len the total length of the finished string
  -- @return str string containing the padded string
  padWithChar = function( str, chr, len )
    return str .. string.rep(chr, len - #str)
  end,
}

return _ENV;
