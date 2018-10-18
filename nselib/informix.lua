---
-- Informix Library supporting a very limited subset of Informix operations
--
-- Summary
-- -------
-- Informix supports both The Open Group Distributed Relational Database
-- Architecture (DRDA) protocol, and their own. This library attempts to
-- implement a basic subset of operations. It currently supports;
--   o Authentication using plain-text usernames and passwords
--   o Simple SELECT, INSERT and UPDATE queries, possible more ...
--
-- Overview
-- --------
-- The library contains the following classes:
--
--   o Packet.*
--    - The Packet classes contain specific packets and function to serialize
--        them to strings that can be sent over the wire. Each class may also
--        contain a function to parse the servers response.
--
--   o ColMetaData
--      - A class holding the meta data for each column
--
--  o Comm
--    - Implements a number of functions to handle communication over the
--        the socket.
--
--  o Helper
--    - A helper class that provides easy access to the rest of the library
--
-- In addition the library contains the following tables with decoder functions
--
--  o MetaDataDecoders
--     - Contains functions to decode the column metadata per data type
--
--  o DataTypeDecoders
--     - Contains function to decode each data-type in the query resultset
--
--  o MessageDecoders
--     - Contains a decoder for each supported protocol message
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
--  helper   = informix.Helper:new( host, port, "on_demo" )
--  status, err = helper:Connect()
--  status, res = helper:Login("informix", "informix")
--  status, err = helper:Close()
-- </code>
--
-- Additional information
-- ----------------------
-- The implementation is based on analysis of packet dumps and has been tested
-- against:
--
-- x IBM Informix Dynamic Server Express Edition v11.50 32-bit on Ubuntu
-- x IBM Informix Dynamic Server xxx 32-bit on Windows 2003
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>
--
-- @args informix.instance specifies the Informix instance to connect to

--
-- Version 0.1
-- Created 07/23/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/28/2010 - v0.2 - added support for SELECT, INSERT and UPDATE
--                             queries
--

local nmap = require "nmap"
local match = require "match"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
_ENV = stdnse.module("informix", stdnse.seeall)

-- A bunch of constants
Constants =
{
  -- A subset of supported messages
  Message = {
    SQ_COMMAND = 0x01,
    SQ_PREPARE = 0x02,
    SQ_ID = 0x04,
    SQ_DESCRIBE = 0x08,
    SQ_EOT = 0x0c,
    SQ_ERR = 0x0d,
    SQ_TUPLE = 0x0e,
    SQ_DONE = 0x0f,
    SQ_DBLIST = 0x1a,
    SQ_DBOPEN = 0x24,
    SQ_EXIT = 0x38,
    SQ_INFO = 0x51,
    SQ_PROTOCOLS = 0x7e,
  },

  -- A subset of supported data types
  DataType = {
    CHAR = 0x00,
    SMALLINT = 0x01,
    INT = 0x02,
    FLOAT = 0x03,
    SERIAL = 0x06,
    DATE = 0x07,
    DATETIME = 0x0a,
    VARCHAR = 0x0d,
  },

  -- These were the ones I ran into when developing :-)
  ErrorMsg = {
    [-201] = "A syntax error has occurred.",
    [-206] = "The specified table is not in the database.",
    [-208] = "Memory allocation failed during query processing.",
    [-258] = "System error - invalid statement id received by the sqlexec process.",
    [-217] = "Column (%s) not found in any table in the query (or SLV is undefined).",
    [-310] = "Table (%s) already exists in database.",
    [-363] = "CURSOR not on SELECT statement.",
    [-555] = "Cannot use a select or any of the database statements in a multi-query prepare.",
    [-664] = "Wrong number of arguments to system function(%s).",
    [-761] = "INFORMIXSERVER does not match either DBSERVERNAME or DBSERVERALIASES.",
    [-951] = "Incorrect password or user is not known on the database server.",
    [-329] = "Database not found or no system permission.",
    [-9628] = "Type (%s) not found.",
    [-23101] = "Unable to load locale categories.",
  }
}

-- The ColMetaData class
ColMetaData = {

  ---Creates a new ColMetaData instance
  --
  -- @return object a new instance of ColMetaData
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sets the datatype
  --
  -- @param typ number containing the datatype
  setType = function( self, typ ) self.type = typ end,

  --- Sets the name
  --
  -- @param name string containing the name
  setName = function( self, name) self.name = name end,


  --- Sets the length
  --
  -- @param len number containing the length of the column
  setLength = function( self, len ) self.len = len end,

  --- Gets the column type
  --
  -- @return typ the column type
  getType = function( self ) return self.type end,

  --- Gets the column name
  --
  -- @return name the column name
  getName = function( self ) return self.name end,

  --- Gets the column length
  --
  -- @return len the column length
  getLength = function( self ) return self.len end,
}

Packet  = {}

-- MetaData decoders used to decode the information for each data type in the
-- meta data returned by the server
--
-- The decoders, should be self explanatory
MetaDataDecoders = {

  [Constants.DataType.INT] = function( data )
    local col_md = ColMetaData:new( )
    local pos = 19

    if ( #data < pos ) then return false, "Failed to decode meta data for data type INT" end

    local len = string.unpack(">I2", data, pos)
    col_md:setLength(len)
    col_md:setType( Constants.DataType.INT )

    return true, col_md
  end,

  [Constants.DataType.CHAR] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then
      return false, "Failed to decode metadata for data type CHAR"
    end
    col_md:setType( Constants.DataType.CHAR )

    return true, col_md
  end,

  [Constants.DataType.VARCHAR] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type CHAR" end
    col_md:setType( Constants.DataType.VARCHAR )

    return true, col_md
  end,

  [Constants.DataType.SMALLINT] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type SMALLINT" end
    col_md:setType( Constants.DataType.SMALLINT )

    return true, col_md
  end,

  [Constants.DataType.SERIAL] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type SMALLINT" end
    col_md:setType( Constants.DataType.SERIAL )

    return true, col_md
  end,

  [Constants.DataType.DATETIME] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type DATETIME" end
    col_md:setType( Constants.DataType.DATETIME )
    col_md:setLength(10)

    return true, col_md
  end,

  [Constants.DataType.FLOAT] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type DATETIME" end
    col_md:setType( Constants.DataType.FLOAT )

    return true, col_md
  end,

  [Constants.DataType.DATE] = function( data )
    local status, col_md = MetaDataDecoders[Constants.DataType.INT]( data )
    if( not(status) ) then return false, "Failed to decode metadata for data type DATETIME" end
    col_md:setType( Constants.DataType.DATE )

    return true, col_md
  end,


}

-- DataType decoders used to decode result set returned from the server
-- This class is still incomplete and some decoders just adjust the offset
-- position rather than decode the value.
--
-- The decoders, should be self explanatory
DataTypeDecoders = {

  [Constants.DataType.INT] = function( data, pos )
    local val, pos = string.unpack(">i4", data, pos)
    return pos, val
  end,

  [Constants.DataType.FLOAT] = function( data, pos )
    local val, pos = string.unpack(">d", data, pos)
    return pos, val
  end,

  [Constants.DataType.DATE] = function( data, pos )
    return pos + 4, "DATE"
  end,

  [Constants.DataType.SERIAL] = function( data, pos )
    local val, pos = string.unpack(">I4", data, pos)
    return pos, val
  end,

  [Constants.DataType.SMALLINT] = function( data, pos )
    local val, pos = string.unpack(">i2", data, pos)
    return pos, val
  end,

  [Constants.DataType.CHAR] = function( data, pos, len )
    local ret, pos = string.unpack("c" .. len, data, pos)
    return pos, Util.ifxToLuaString( ret )
  end,

  [Constants.DataType.VARCHAR] = function( data, pos, len )
    local ret, pos = string.unpack("s1", data, pos)
    return pos, Util.ifxToLuaString( ret )
  end,

  [Constants.DataType.DATETIME] = function( data, pos )
    return pos + 10, "DATETIME"
  end,

}


-- The MessageDecoders class "holding" the Response Decoders
MessageDecoders = {

  --- Decodes the SQ_ERR error message
  --
  -- @param socket already connected to the Informix database server
  -- @return status true on success, false on failure
  -- @return errmsg, Informix error message or decoding error message if
  --         status is false
  [Constants.Message.SQ_ERR] = function( socket )
    local status, data = socket:receive_buf(match.numbytes(8), true)
    local errmsg, str

    if( not(status) ) then return false, "Failed to decode error response" end

    local svcerr, oserr, _, len, pos = string.unpack(">i2i2i2i2", data )

    if( len and len > 0 ) then
      status, data = socket:receive_buf(match.numbytes(len), true)
      if( not(status) ) then return false, "Failed to decode error response" end
      if #data ~= len then return false, "Failed to receive entire error response" end
      str = data
    end

    status, data = socket:receive_buf(match.numbytes(2), true)

    errmsg = Constants.ErrorMsg[svcerr]
    if ( errmsg and str ) then
      errmsg = errmsg:format(str)
    end
    return false, errmsg or ("Informix returned an error (svcerror: %d, oserror: %d)"):format( svcerr, oserr )
  end,

  --- Decodes the SQ_PROTOCOLS message
  --
  -- @param socket already connected to the Informix database server
  -- @return status true on success, false on failure
  -- @return err error message if status is false
  [Constants.Message.SQ_PROTOCOLS] = function( socket )
    local status, data
    local len, _

    status, data = socket:receive_buf(match.numbytes(2), true)
    if( not(status) ) then return false, "Failed to decode SQ_PROTOCOLS response" end
    len = string.unpack(">I2", data )

    -- read the remaining data
    return socket:receive_buf(match.numbytes(len + 2 + len % 2), true)
  end,

  --- Decodes the SQ_EOT message
  --
  -- @return status, always true
  [Constants.Message.SQ_EOT] = function( socket )
    return true
  end,

  --- Decodes the SQ_DONE message
  --
  -- @param socket already connected to the Informix database server
  -- @return status true on success, false on failure
  -- @return err error message if status is false
  [Constants.Message.SQ_DONE] = function( socket )
    local status, data = socket:receive_buf(match.numbytes(2), true)
    local _, len, tmp
    if( not(status) ) then return false, "Failed to decode SQ_DONE response" end
    len = string.unpack(">I2", data )

    -- For some *@#! reason the SQ_DONE packet sometimes contains an
    -- length exceeding the length of the packet by one. Attempt to
    -- detect this and fix.
    status, data = socket:receive_buf(match.numbytes(len), true)
    tmp = string.unpack(">I2", data, len - 2)
    return socket:receive_buf(match.numbytes((tmp == 0) and 3 or 4), true)
  end,

  --- Decodes the metadata for a result set
  --
  -- @param socket already connected to the Informix database server
  -- @return status true on success, false on failure
  -- @return column_meta table containing the metadata
  [Constants.Message.SQ_DESCRIBE] = function( socket )
    local status, data = socket:receive_buf(match.numbytes(14), true)
    local pos, cols, col_type, col_name, col_len, col_md, stmt_id
    local coldesc_len, x
    local column_meta = {}

    if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end
    cols, coldesc_len, pos = string.unpack(">I2I2", data, 11)
    stmt_id, pos = string.unpack(">I2", data, 3)

    if ( cols <= 0 ) then
      -- We can end up here if we executed a CREATE, UPDATE OR INSERT statement
      local tmp
      status, data = socket:receive_buf(match.numbytes(2), true)
      if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end

      tmp, pos = string.unpack(">I2", data)

      -- This was the result of a CREATE or UPDATE statement
      if ( tmp == 0x0f ) then
        status, data = socket:receive_buf(match.numbytes(26), true)
      -- This was the result of a INSERT statement
      elseif( tmp == 0x5e ) then
        status, data = socket:receive_buf(match.numbytes(46), true)
      end
      return true
    end

    status, data = socket:receive_buf(match.numbytes(6), true)
    if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end

    for i=1, cols do

      status, data = socket:receive_buf(match.numbytes(2), true)
      if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end
      col_type, pos = string.unpack("B", data, 2)

      if ( MetaDataDecoders[col_type] ) then

        status, data = socket:receive_buf(match.numbytes(20), true)
        if( not(status) ) then
          return false, "Failed to read column meta data"
        end

        status, col_md = MetaDataDecoders[col_type]( data )
        if ( not(status) ) then
          return false, col_md
        end
      else
        return false, ("No metadata decoder for column type: %d"):format(col_type)
      end

      if ( i<cols ) then
        status, data = socket:receive_buf(match.numbytes(6), true)
        if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end
      end

      col_md:setType( col_type )
      table.insert( column_meta, col_md )
    end

    status, data = socket:receive_buf(match.numbytes(coldesc_len + coldesc_len % 2), true)
    if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end
    pos = 1

    for i=1, cols do
      local col_name
      col_name, pos = string.unpack("z", data, pos)
      column_meta[i]:setName( col_name )
    end

    status, data = socket:receive_buf(match.numbytes(2), true)
    if( not(status) ) then return false, "Failed to decode SQ_DESCRIBE response" end

    data, pos = string.unpack(">I2", data)
    if( data == Constants.Message.SQ_DONE ) then
      status, data = socket:receive_buf(match.numbytes(26), true)
    else
      status, data = socket:receive_buf(match.numbytes(10), true)
    end
    return true, { metadata = column_meta, stmt_id = stmt_id }
  end,

  --- Processes the result from a query
  --
  -- @param socket already connected to the Informix database server
  -- @param info table containing the following fields:
  --        <code>metadata</code> as received from <code>SQ_DESCRIBE</code>
  --        <code>rows</code> containing already retrieved rows
  --        <code>id</code> containing the statement id as sent to SQ_ID
  -- @return status true on success, false on failure
  -- @return rows table containing the resulting columns and rows as:
  --         { { col, col2, col3 } }
  --         or error message if status is false
  [Constants.Message.SQ_TUPLE] = function( socket, info )
    local status, data
    local row = {}
    local count = 1

    if ( not( info.rows ) ) then info.rows = {} end

    while (true) do
      local pos = 1

      status, data = socket:receive_buf(match.numbytes(6), true)
      if( not(status) ) then return false, "Failed to read column data" end

      local total_len = string.unpack(">I4", data, 3)
      status, data = socket:receive_buf(match.numbytes(total_len + total_len % 2), true)
      if( not(status) ) then return false, "Failed to read column data" end

      row = {}
      for _, col in ipairs(info.metadata) do
        local typ, len, name = col:getType(), col:getLength(), col:getName()
        local val

        if( DataTypeDecoders[typ] ) then
          pos, val = DataTypeDecoders[typ]( data, pos, len )
        else
          return false, ("No data type decoder for type: 0x%d"):format(typ)
        end
        table.insert( row, val )
      end

      status, data = socket:receive_buf(match.numbytes(2), true)

      local flags = string.unpack(">I2", data)

      count = count + 1
      table.insert( info.rows, row )

      -- Check if we're done
      if ( Constants.Message.SQ_DONE == flags ) then
        break
      end

      -- If there's more data we need to send a new SQ_ID packet
      if ( flags == Constants.Message.SQ_EOT ) then
        local status, tmp = socket:send( tostring(Packet.SQ_ID:new( info.id, nil, "continue" ) ) )
        local pkt_type

        status, tmp = socket:receive_buf(match.numbytes(2), true)
        pkt_type, pos = string.unpack(">I2", tmp)

        return MessageDecoders[pkt_type]( socket, info )
      end

    end

    -- read the remaining data
    status, data = socket:receive_buf(match.numbytes(26), true)
    if( not(status) ) then return false, "Failed to read column data" end

    -- signal finish reading
    status, data = socket:send( tostring(Packet.SQ_ID:new( info.id, nil, "end" ) ) )
    status, data = socket:receive_buf(match.numbytes(2), true)

    return true, info

  end,

  --- Decodes a SQ_DBLIST response
  --
  -- @param socket already connected to the Informix database server
  -- @return status true on success, false on failure
  -- @return databases array of database names
  [Constants.Message.SQ_DBLIST] = function( socket )

    local status, data, pos, len, db
    local databases = {}

    while( true ) do
      status, data = socket:receive_buf(match.numbytes(2), true)
      if ( not(status) ) then return false, "Failed to parse SQ_DBLIST response" end

      len, pos = string.unpack(">I2", data)
      if ( 0 == len ) then break end

      status, data = socket:receive_buf(match.numbytes(len + len % 2), true)
      if ( not(status) ) then return false, "Failed to parse SQ_DBLIST response" end

      db, pos = string.unpack("c" .. len, data )
      table.insert( databases, db )
    end

    -- read SQ_EOT
    status, data = socket:receive_buf(match.numbytes(2), true)

    return true, databases
  end,

  [Constants.Message.SQ_EXIT] = function( socket )
    local status, data = socket:receive_buf(match.numbytes(2), true)
    if ( not(status) ) then return false, "Failed to parse SQ_EXIT response" end

    return true
  end


}

-- Packet used to request a list of available databases
Packet.SQ_DBLIST =
{
  --- Creates a new Packet.SQ_DBLIST instance
  --
  -- @return object new instance of Packet.SQ_DBLIST
  new = function( self )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2I2", Constants.Message.SQ_DBLIST, Constants.Message.SQ_EOT)
  end

}

-- Packet used to open the database
Packet.SQ_DBOPEN =
{

  --- Creates a new Packet.SQ_DBOPEN instance
  --
  -- @param database string containing the name of the database to open
  -- @return object new instance of Packet.SQ_DBOPEN
  new = function( self, database )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.database = database
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2I2", Constants.Message.SQ_DBOPEN, #self.database)
      .. Util.padToOdd(self.database)
      .. string.pack(">I2I2", 0x00, Constants.Message.SQ_EOT)
  end

}

-- This packet is "a mess" and requires further analysis
Packet.SQ_ID =
{
  --- Creates a new Packet.SQ_ID instance
  --
  -- @param id number containing the statement identifier
  -- @param s1 number unknown, should be 0 on first call and 1 when more data is requested
  -- @return object new instance of Packet.SQ_ID
  new = function( self, id, id2, mode )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.id = ("_ifxc%.13d"):format( id2 or 0 )
    o.seq = id
    o.mode = mode
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    if ( self.mode == "continue" ) then
      return string.pack( ">I2I2I2I2I2I2",  Constants.Message.SQ_ID, self.seq, 0x0009, 0x1000, 0x0000, Constants.Message.SQ_EOT )
    elseif ( self.mode == "end" ) then
      return string.pack( ">I2I2I2I2", Constants.Message.SQ_ID, self.seq, 0x000a, Constants.Message.SQ_EOT)
    else
      return string.pack(">I2I2I2s2I2I2I2I2I2I2I2", Constants.Message.SQ_ID, self.seq, 0x0003, self.id,
      0x0006, 0x0004, self.seq, 0x0009, 0x1000, 0x0000, Constants.Message.SQ_EOT )
    end
  end

}

Packet.SQ_INFO =
{

  -- The default parameters
  DEFAULT_PARAMETERS = {
    [1] = { ["DBTEMP"] = "/tmp" },
    [2] = { ["SUBQCACHESZ"] = "10" },
  },

  --- Creates a new Packet.SQ_INFO instance
  --
  -- @param params containing any additional parameters to use
  -- @return object new instance of Packet.SQ_INFO
  new = function( self, params )
    local o = {}
    local params = params or Packet.SQ_INFO.DEFAULT_PARAMETERS
    setmetatable(o, self)
    self.__index = self
    o.parameters = {}

    for _, v in ipairs( params ) do
      for k2, v2 in pairs(v) do
        o:addParameter( k2, v2 )
      end
    end
    return o
  end,

  addParameter = function( self, key, value )
    table.insert( self.parameters, { [key] = value } )
  end,

  paramToString = function( self, key, value )
    return string.pack(">I2", #key)
    .. Util.padToOdd(key)
    .. string.pack(">I2", #value)
    .. Util.padToOdd( value )
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function( self )
    local params = ""
    local data

    for _, v in ipairs( self.parameters ) do
      for k2, v2 in pairs( v ) do
        params = params .. self:paramToString( k2, v2 )
      end
    end

    data = string.pack(">I2I2I2I2I2", Constants.Message.SQ_INFO, 0x0006, #params + 6, 0x000c, 0x0004)
    .. params
    .. string.pack(">I2I2I2", 0x0000, 0x0000, Constants.Message.SQ_EOT)
    return data
  end
}

-- Performs protocol negotiation?
Packet.SQ_PROTOCOLS =
{
  -- hex-encoded data to send as protocol negotiation
  data = stdnse.fromhex("0007fffc7ffc3c8c8a00000c"),

  --- Creates a new Packet.SQ_PROTOCOLS instance
  --
  -- @return object new instance of Packet.SQ_PROTOCOLS
  new = function( self )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2", Constants.Message.SQ_PROTOCOLS) .. self.data
  end

}

-- Packet used to execute SELECT Queries
Packet.SQ_PREPARE =
{

  --- Creates a new Packet.SQ_PREPARE instance
  --
  -- @param query string containing the query to execute
  -- @return object new instance of Packet.SQ_PREPARE
  new = function( self, query )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.query = Util.padToEven(query)
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2s4xI2I2I2", Constants.Message.SQ_PREPARE, self.query, 0x0016, 0x0031, Constants.Message.SQ_EOT)
  end

}

-- Packet used to execute commands other than SELECT
Packet.SQ_COMMAND =
{

  --- Creates a new Packet.SQ_COMMAND instance
  --
  -- @param query string containing the query to execute
  -- @return object new instance of Packet.SQ_COMMAND
  new = function( self, query )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.query = Util.padToEven(query)
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2s4xI2I2I2I2", Constants.Message.SQ_COMMAND, self.query, 0x0016, 0x0007, 0x000b, Constants.Message.SQ_EOT)
  end

}

Packet.SQ_EXIT = {

  --- Creates a new Packet.SQ_EXIT instance
  --
  -- @return object new instance of Packet.SQ_EXIT
  new = function( self )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function(self)
    return string.pack(">I2", Constants.Message.SQ_EXIT)
  end

}

-- The Utility Class
Util =
{
  --- Converts a connection parameter to string
  --
  -- @param param string containing the parameter name
  -- @param value string containing the parameter value
  -- @return string containing the encoded parameter as string
  paramToString = function( param, value )
    return string.pack(">s2s2", param, value )
  end,

  --- Pads a string to an even number of characters
  --
  -- @param str the string to pad
  -- @param pad the character to pad with
  -- @return result the padded string
  padToEven = function( str, pad )
    return (#str % 2 == 1) and str or str .. ( pad and pad or "\0")
  end,

  --- Pads a string to an odd number of characters
  --
  -- @param str the string to pad
  -- @param pad the character to pad with
  -- @return result the padded string
  padToOdd = function( str, pad )
    return (#str % 2 == 0) and str or str .. ( pad and pad or "\0")
  end,

  --- Formats a table to suitable script output
  --
  -- @param info as returned from ExecutePrepare
  -- @return table suitable for use by <code>stdnse.format_output</code>
  formatTable = function( info )
    local header, row = "", ""
    local result = {}
    local metadata = info.metadata
    local rows = info.rows

    if ( info.error ) then
      table.insert(result, info.error)
      return result
    end

    if ( info.info ) then
      table.insert(result, info.info)
      return result
    end

    if ( not(metadata) ) then return "" end

    for i=1, #metadata do
      if ( metadata[i]:getType() == Constants.DataType.CHAR and metadata[i]:getLength() < 50) then
        header = header .. ("%-" .. metadata[i]:getLength() .. "s "):format(metadata[i]:getName())
      else
        header = header .. metadata[i]:getName()
        if ( i<#metadata ) then
          header = header .. "\t"
        end
      end
    end
    table.insert( result, header )

    for j=1, #rows do
      row = ""
      for i=1, #metadata do
        row = row .. rows[j][i] .. " "
        if ( metadata[i]:getType() ~= Constants.DataType.CHAR and i<#metadata and metadata[i]:getLength() < 50 ) then row = row .. "\t" end
      end
      table.insert( result, row )
    end

    return result
  end,

  -- Removes trailing nulls
  --
  -- @param str containing the informix string
  -- @return ret the string with any trailing nulls removed
  ifxToLuaString = function( str )
    local ret

    if ( not(str) ) then return "" end

    if ( str:sub(-1, -1 ) ~= "\0" ) then
      return str
    end

    for i=1, #str do
      if ( str:sub(-i,-i) == "\0" ) then
        ret = str:sub(1, -i - 1)
      else
        break
      end
    end

    return ret
  end,
}

-- The connection Class, used to connect and authenticate to the server
-- Currently only supports plain-text authentication
--
-- The unknown portions in the __tostring method have been derived from Java
-- code connecting to Informix using JDBC.
Packet.Connect = {

  -- default parameters sent using JDBC
  DEFAULT_PARAMETERS = {
    [1] = { ['LOCKDOWN'] = 'no' },
    [2] = { ['DBDATE'] = 'Y4MD-' },
    [3] = { ['SINGLELEVEL'] = 'no' },
    [4] = { ['NODEFDAC'] = 'no' },
    [5] = { ['CLNT_PAM_CAPABLE'] = '1' },
    [6] = { ['SKALL'] = '0' },
    [7] = { ['LKNOTIFY'] = 'yes' },
    [8] = { ['SKSHOW'] = '0' },
    [9] = { ['IFX_UPDDESC'] = '1' },
    [10] = { ['DBPATH'] = '.' },
    [11] = { ['CLIENT_LOCALE'] = 'en_US.8859-1' },
    [12] = { ['SKINHIBIT'] = '0' },
  },

  --- Creates a new Connection packet
  --
  -- @param username string containing the username for authentication
  -- @param password string containing the password for authentication
  -- @param instance string containing the instance to connect to
  -- @return a new Packet.Connect instance
  new = function(self, username, password, instance, parameters)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.username = username and username .. "\0"
    o.password = password and password .. "\0"
    o.instance = instance and instance .. "\0"
    o.parameters = parameters
    return o
  end,

  --- Adds the default set of parameters
  addDefaultParameters = function( self )
    for _, v in ipairs( self.DEFAULT_PARAMETERS ) do
      for k2, v2 in pairs( v ) do
        self:addParameter( k2, v2 )
      end
    end
  end,

  --- Adds a parameter to the connection packet
  --
  -- @param param string containing the parameter name
  -- @param value string containing the parameter value
  -- @return status, always true
  addParameter = function( self, param, value )
    local tbl = {}
    tbl[param] = value
    table.insert( self.parameters, tbl )

    return true
  end,

  --- Retrieves the OS error code
  --
  -- @return oserror number containing the OS error code
  getOsError = function( self ) return self.oserror end,

  --- Retrieves the Informix service error
  --
  -- @return svcerror number containing the service error
  getSvcError = function( self ) return self.svcerror end,

  --- Retrieves the Informix error message
  --
  -- @return errmsg string containing the "mapped" error message
  getErrMsg = function( self ) return self.errmsg end,

  --- Reads and decodes the response to the connect packet from the server.
  --
  -- The function will return true even if the response contains an Informix
  -- error. In order to verify if the connection was successful, check for OS
  -- or service errors using the getSvcError and getOsError methods.
  --
  -- @param socket already connected to the server
  -- @return status true on success, false on failure
  -- @return err msg if status is false
  readResponse = function( self, socket )
    local status, data = socket:receive_buf(match.numbytes(2), true)
    local len, pos, tmp

    if ( not(status) ) then return false, data end
    len, pos = string.unpack(">I2", data)
    status, data = socket:receive_buf(match.numbytes(len - 2), true)
    if ( not(status) ) then return false, data end

    pos = 13
    tmp, pos = string.unpack(">I2", data, pos)
    pos = pos + tmp

    tmp, pos = string.unpack(">I2", data, pos)

    if ( 108 ~= tmp ) then
      return false, "Connect received unexpected response"
    end

    pos = pos + 12
    -- version
    self.version, pos = string.unpack(">s2", data, pos)

    -- serial
    self.serial, pos = string.unpack(">s2", data, pos)

    -- applid
    self.applid, pos = string.unpack(">s2", data, pos)

    -- skip 14 bytes ahead
    pos = pos + 14

    -- do some more skipping
    tmp, pos = string.unpack(">I2", data, pos)
    pos = pos + tmp

    -- do some more skipping
    tmp, pos = string.unpack(">I2", data, pos)
    pos = pos + tmp

    -- skip another 24 bytes
    pos = pos + 24
    tmp, pos = string.unpack(">I2", data, pos)

    if ( tmp ~= 102 ) then
      return false, "Connect received unexpected response"
    end

    pos = pos + 6
    self.svcerror, self.oserror, pos = string.unpack(">i2i2", data, pos )

    if ( self.svcerror ~= 0 ) then
      self.errmsg = Constants.ErrorMsg[self.svcerror] or ("Unknown error %d occurred"):format( self.svcerror )
    end

    return true
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function( self )
    local data
    local unknown = [[
    013c0000006400650000003d0006494545454d00006c73716c65786563000000
    00000006392e32383000000c524453235230303030303000000573716c690000
    00013300000000000000000001
    ]]

    local unknown2 = [[
    6f6c0000000000000000003d746c697463700000000000010068000b
    00000003
    ]]

    local unknown3 = [[
    00000000000000000000006a
    ]]

    local unknown4 = [[ 007f ]]

    if ( not(self.parameters) ) then
      self.parameters = {}
      self:addDefaultParameters()
    end

    data = {
      stdnse.fromhex(unknown),
      string.pack(">s2s2", self.username, self.password),
      stdnse.fromhex(unknown2),
      string.pack(">s2", self.instance),
      stdnse.fromhex(unknown3),
      string.pack(">I2", #self.parameters),
    }

    if ( self.parameters ) then
      for _, v in ipairs( self.parameters ) do
        for k2, v2 in pairs( v ) do
          data[#data+1] = Util.paramToString( k2 .. "\0", v2 .. "\0" )
        end
      end
    end

    data[#data+1] = stdnse.fromhex(unknown4)
    data = table.concat(data)
    data = string.pack(">I2", #data + 2) .. data

    return data
  end,


}

-- The communication class
Comm =
{
  --- Creates a new Comm instance
  --
  -- @param socket containing a buffered socket connected to the server
  -- @return a new Comm instance
  new = function(self, socket)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.socket = socket
    return o
  end,

  --- Sends and packet and attempts to handle the response
  --
  -- @param packets an instance of a Packet.* class
  -- @param info any additional info to pass as the second parameter to the
  --        decoder
  -- @return status true on success, false on failure
  -- @return data returned from the ResponseDecoder
  exchIfxPacket = function( self, packet, info )
    local _, typ
    local status, data = self.socket:send( tostring(packet) )
    if ( not(status) ) then return false, data end

    status, data = self.socket:receive_buf(match.numbytes(2), true)
    typ = string.unpack(">I2", data)

    if ( MessageDecoders[typ] ) then
      status, data = MessageDecoders[typ]( self.socket, info )
    else
      return false, ("Unsupported data returned from server (type: 0x%x)"):format(typ)
    end

    return status, data
  end

}

-- The Helper class providing easy access to the other db functionality
Helper = {

  --- Creates a new Helper instance
  --
  -- @param host table as passed to the action script function
  -- @param port table as passed to the action script function
  -- @param instance [optional] string containing the instance to connect to
  --        in case left empty it's populated by the informix.instance script
  --        argument.
  -- @return Helper instance
  new = function(self, host, port, instance)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.instance = instance or "nmap_probe"
    return o
  end,

  --- Connects to the Informix server
  --
  -- @return true on success, false on failure
  -- @return err containing error message when status is false
  Connect = function( self, socket )
    local status, data
    local conn, packet
    self.socket = socket or nmap.new_socket()

    -- Some Informix server seem to take a LOT of time to respond?!
    self.socket:set_timeout(20000)
    status, data = self.socket:connect( self.host.ip, self.port.number, "tcp" )

    if( not(status) ) then
      return status, data
    end

    self.comm = Comm:new( self.socket )

    return true
  end,

  --- Attempts to login to the Informix database server
  --
  -- The optional parameters parameter takes any informix specific parameters
  -- used to connect to the database. In case it's omitted a set of default
  -- parameters are set. Parameters should be past as key, value pairs inside
  -- of a table array as the following example:
  --
  -- local params = {
  --   [1] = { ["PARAM1"] = "VALUE1" },
  --   [2] = { ["PARAM2"] = "VALUE2" },
  -- }
  --
  -- @param username string containing the username for authentication
  -- @param password string containing the password for authentication
  -- @param parameters [optional] table of informix specific parameters
  -- @param database [optional] database to connect to
  -- @param retry [optional] used when autodetecting instance
  -- @return status true on success, false on failure
  -- @return err containing the error message if status is false
  Login = function( self, username, password, parameters, database, retry )
    local conn, status, data, len, packet

    conn = Packet.Connect:new( username, password, self.instance, parameters )

    status, data = self.socket:send( tostring(conn) )
    if ( not(status) ) then return false, "Helper.Login failed to send login request" end
    status = conn:readResponse( self.socket )
    if ( not(status) ) then return false, "Helper.Login failed to read response" end

    if ( status and ( conn:getOsError() ~= 0  or conn:getSvcError() ~= 0 )  ) then
      -- Check if we didn't supply the correct instance name, if not attempt to
      -- reconnect using the instance name returned by the server
      if ( conn:getSvcError() == -761 and not(retry) ) then
        self.instance = conn.applid
        self:Close()
        self:Connect()
        return self:Login( username, password, parameters, database, 1 )
      end
      return false, conn:getErrMsg()
    end

    status, packet = self.comm:exchIfxPacket( Packet.SQ_PROTOCOLS:new() )
    if ( not(status) ) then return false, packet end

    status, packet = self.comm:exchIfxPacket( Packet.SQ_INFO:new() )
    if ( not(status) ) then return false, packet end

    -- If a database was supplied continue further protocol negotiation and
    -- attempt to open the database.
    if ( database ) then
      status, packet = self:OpenDatabase( database )
      if ( not(status) ) then return false, packet end
    end

    return true
  end,

  --- Opens a database
  --
  -- @param database string containing the database name
  -- @return status true on success, false on failure
  -- @return err string containing the error message if status is false
  OpenDatabase = function( self, database )
    return self.comm:exchIfxPacket( Packet.SQ_DBOPEN:new( database ) )
  end,

  --- Attempts to retrieve a list of available databases
  --
  -- @return status true on success, false on failure
  -- @return databases array of database names or err on failure
  GetDatabases = function( self )
    return self.comm:exchIfxPacket( Packet.SQ_DBLIST:new() )
  end,

  Query = function( self, query )
    local status, metadata, data, res
    local id, seq = 0, 1
    local result = {}

    if ( type(query) == "string" ) then
      query = stringaux.strsplit(";%s*", query)
    end

    for _, q in ipairs( query ) do
      if ( q:upper():match("^%s*SELECT") ) then
        status, data = self.comm:exchIfxPacket( Packet.SQ_PREPARE:new( q ) )
        seq = seq + 1
      else
        status, data = self.comm:exchIfxPacket( Packet.SQ_COMMAND:new( q .. ";" ) )
      end

      if( status and data ) then
        metadata = data.metadata
        status, data = self.comm:exchIfxPacket( Packet.SQ_ID:new( data.stmt_id, seq, "begin" ), { metadata = metadata, id = id, rows = nil, query=q }  )

        -- check if any rows were returned
        if ( not( data.rows ) ) then
          data = { query = q, info = "No rows returned" }
        end
        --if( not(status) ) then return false, data end
      elseif( not(status) ) then
        data = { query = q, ["error"] = "ERROR: " .. data }
      else
        data = { query = q, info = "No rows returned" }
      end
      table.insert( result, data )
    end

    return true, result
  end,

  --- Closes the connection to the server
  --
  -- @return status true on success, false on failure
  Close = function( self )
    local status, packet = self.comm:exchIfxPacket( Packet.SQ_EXIT:new() )
    return self.socket:close()
  end,

}

return _ENV;
