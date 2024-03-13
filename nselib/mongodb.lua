---
-- Library methods for handling MongoDB, creating and parsing packets.
--
-- @author Martin Holst Swende
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @args mongodb.db - the database to use for authentication

-- Created 01/13/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Revised 01/03/2012 - v0.2 - added authentication support <patrik@cqure.net>

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("mongodb", stdnse.seeall)


-- this is not yet widely implemented but at least used for authentication
-- ideally, it would be used to set the database against which operations,
-- that do not require a specific database, should run
local arg_DB = stdnse.get_script_args("mongodb.db")

-- Some lazy shortcuts

local function dbg(str,...)
  stdnse.debug3("MngoDb:"..str, ...)
end

----------------------------------------------------------------------
-- First of all comes a Bson parsing library. This can easily be moved out into a separate library should other
-- services start to use Bson
----------------------------------------------------------------------
-- Library methods for handling the BSON format
--
-- For more documentation about the BSON format,
---and more details about its implementations, check out the
-- python BSON implementation which is available at
-- http://github.com/mongodb/mongo-python-driver/blob/master/bson/
-- and licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0)
--
-- @author Martin Holst Swende
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Version 0.1

-- Created 01/13/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
--module("bson", package.seeall)
local function dbg_err(str,...)
  stdnse.debug2("Bson-ERR:"..str, ...)
end

--Converts an element (key, value) into bson binary data
--@param key the key name, must *NOT* contain . (period) or start with $
--@param value, the element value
--@return status : true if ok, false if error
--@return result : the packed binary data OR error message
local function _element_to_bson(key, value)

  --Some constraints-checking
  if type(key) ~= 'string' then
    return false, "Documents must have only string keys, key was " .. type(key)
  end
  if key:sub(1,1) == "$" then
    return false,  "key must not start with $: ".. key
  end
  if key:find("%.") then
    return false, ("key %s must not contain '.'"):format(tostring(key))
  end

  if type(value) == 'string' then
    -- must null-terminate string first
    return true, string.pack("<B z <s4", 0x02, key, value .. "\0")
  elseif type(value) =='table' then
    local status, bsonval = toBson(value)
    if status then
      bsonval = string.pack("<B z", 0x03, key) .. bsonval
    end
    return status, bsonval
  elseif type(value)== 'boolean' then
    return true, string.pack("<B z B", 0x08, key, value and 1 or 0)
  elseif type(value) == 'number' then
    if math.type(value) == "integer" then
      if value > 0x7fffffff or value < -0x80000000 then -- long
        return true, string.pack("<B z i8", 0x12, key, value)
      else -- int32
        return true, string.pack("<B z i4", 0x10, key, value)
      end
    else
      return true, string.pack("<B z d", 0x01, key, value)
    end
  end

  local _ = ("cannot convert value of type %s to bson"):format(type(value))
  return false, _
end

--Converts a table of elements to binary bson format
--@param dict the table
--@return status : true if ok, false if error
--@return result : a string of binary data OR error message
function toBson(dict)

  local elements = ""
  --Put id first
  if dict._id then
    local status,res = _element_to_bson("_id", dict._id)
    if not status then return false, res end
    elements = elements..res
  elseif ( dict._cmd ) then
    for k, v in pairs(dict._cmd) do
      local status,res = _element_to_bson(k, v)
      if not status then return false, res end
      elements = elements..res
    end
  end
  --Concatenate binary values
  for key, value in pairs( dict ) do
    if key ~= "_id" and key ~= "_cmd" then
      dbg("dictionary to bson : key,value =(%s,%s)",key,value)
      local status,res = _element_to_bson(key,value)
      if not status then return false, res end
      elements = elements..res
    end
  end
  -- Get length
  local length = #elements + 5

  if length > 4 * 1024 * 1024 then
    return false, "document too large - BSON documents are limited to 4 MB"
  end
  dbg("Packet length is %d",length)
  --Final pack
  return true, string.pack("<I4", length) .. elements .. "\0"
end

-- Reads a null-terminated string.
--@param data the data which starts with a c-string
--@return the string
--@return the remaining data (*without* null-char)
local function get_c_string(data)
  local nullpos, nextpos = string.find(data, "\0")
  if not nullpos then
    dbg_err("C-string did not contain NULL char")
    return nil, data
  end
  return data:sub(1, nullpos - 1), data:sub(nextpos + 1)
end

local function get_bson_str (data)
  local v, pos = string.unpack("<s4", data)
  if not v or #v < 1 or v:byte(-1) ~= 0 then -- must be null-terminated
    return nil, 0, "String not null-terminated or too short"
  end
  return v:sub(1,-2), pos -- strip the null
end

local function get_bson_obj (data)
  local object, err

  -- Need to know the length, to return later
  local obj_size = string.unpack("<i4", data)
  -- Now, get the data object
  dbg("Recursing into bson array")
  object, data, err = fromBson(data)
  dbg("Recurse finished, got data object")
  -- And return where the parsing stopped
  return object, obj_size+1, err
end

-- @field name BSON type name
-- @field min Minumum number of bytes that must be present to parse the value (default: string.packsize(format)
-- @field format A format string for string.unpack, for simplest types
-- @field parse A function to parse the value. Returns value and pos, or nil and error
local BSON_ELEMENTS = {
  [0x00] = { name = "EOO", format = "c0" },
  [0x01] = { name = "BSONNUM", -- Floating point, 8 bytes
    min = 8, format = "<d"
  },
  [0x02] = {name = "BSONSTR", -- string
    min = 4,
    parse = get_bson_str
  },
  [0x03] = {name = "BSONOBJ", -- object
    min = 4,
    parse = get_bson_obj
  },
  [0x04] = {name = "BSONARR", -- Array
    min = 4,
    parse = get_bson_obj
  },
  [0x05] = {name = "BSONBIN", -- BSON binary or UUID
    min = 5,
    parse = function (data)
      local binlen, subtype, pos = string.unpack("<I4 B", data)
      if subtype == 2 then
        local sublen, pos = string.unpack("<I4", data, pos)
        if sublen ~= binlen - 4 then
          return nil, 0, "Binary subtype 2 length mismatch"
        end
        binlen = sublen
      end
      local binstr = string.unpack(("c%d"):format(binlen), data, pos)
      return ("Binary subtype %d: %s"):format(subtype, stdnse.tohex(binstr)), pos + binlen
    end
  },
  [0x06] = {name = "BSONUND", min = 0, parse = function () return nil, 0 end}, -- "undefined"
  [0x07] = {name = "BSONOID", format = "c12"}, -- Object ID
  [0x08] = {name = "BSONBOO", -- boolean
    min = 1,
    parse = function (data)
      return data:byte(1) == 1, 2
    end
  },
  [0x09] = {name = "BSONDAT", format = "<i8"}, -- int64, UTC datetime
  [0x0a] = {name = "BSONNUL", min = 0, parse = function () return nil, 0 end}, -- NULL
  [0x0b] = {name = "BSONRGX",
    min = 2,
    parse = function (data)
      local pattern, flags, pos = string.unpack("zz", data)
      return ("/%s/%s"):format(pattern, flags), pos
    end
  },
  [0x0c] = {name = "BSONREF", -- DBRef (deprecated)
    min = 13,
    parse = function (data)
      local collection, oid, pos = string.unpack("z c12", data)
      return ("DBRef(%s, %s)"):format(collection, oid), pos
    end
  },
  [0x0d] = {name = "BSONCOD", -- code
    min = 4,
    parse = get_bson_str
  },
  [0x0e] = {name = "BSONSYM", -- symbol (deprecated)
    min = 4,
    parse = get_bson_str
  },
  [0x0f] = {name = "BSONCWS", -- code with scope
    min = 8,
    parse = function (data)
      local codeobj, pos = string.unpack("<s4", data)
      local code, pos2 = string.unpack("<s4", codeobj)
      local scope, _, err = fromBson(codeobj:sub(pos2))
      if err then
        return nil, 0, err
      end
      -- TODO: return an object, not a string?
      return ("Code with scope: %s"):format(code), pos
    end
  },
  [0x10] = {name = "BSONINT", format = "<i4"}, -- 32-bit int
  [0x11] = {name = "BSONTIM",
    min = 8,
    parse = function (data)
      local inc, timestamp, pos = string.unpack("<I4 I4", data)
      return ("Timestamp(%u, %u)"):format(timestamp, inc), pos
    end
  },
  [0x12] = {name = "BSONLON", format = "<i8"}, -- 64-bit long int
  [0x13] = {name = "BSONDEC", -- 128-bit IEEE 754-2008 decimal float in Binary Integer Decimal
    min = 16,
    parse = function (data)
      local bid, pos = string.unpack("c16", data)
      return ("Decimal128(%s)"):format(stdnse.tohex(bid)), pos
    end
  },
}
-- Element parser. Parse data elements
-- @param data String containing binary data
-- @return Position in the data string where parsing stopped
-- @return Unpacked value
-- @return error string if error occurred
local function parse(code,data)
  local getter = BSON_ELEMENTS[code]
  local err
  if not getter then
    err = ("Getter for %d not implemented"):format(code)
    return 0, nil, err
  end
  dbg("Decoding %s", getter.name)

  local min = 0
  if getter.min then
    min = getter.min
  elseif getter.format then
    local status, m = pcall(string.packsize, getter.format)
    if status then
      min = m
    end
    -- Set it to save time later
    getter.min = min
  end
  if #data < min then
    return 0, nil, ("Not enough bytes for %s, needed %d"):format(getter.name, min)
  end

  local status, v, pos
  if getter.format then
    status, v, pos = pcall(string.unpack, getter.format, data)
  else
    status, v, pos, err = pcall(getter.parse, data)
  end
  if not status then
    -- strip the module name (e.g. /path/to/mongodb.lua:)
    err = v:gsub(".-:", "", 1)
    pos = 0
    v = nil
  end
  return pos, v, err
end


-- Reads an element from binary to BSon
--@param data a string of data to convert
--@return Name of the element
--@return Value of the element
--@return Residual data not used
--@return any error that occurred
local function _element_to_dict(data)
  local element_type, element_name, err, pos, value
  --local element_size = data:byte(1)
  element_type = data:byte(1)
  element_name, data = get_c_string(data:sub(2))
  if not element_name then
    return nil, nil, data, "Bad element name"
  end

  dbg(" Read element name '%s' (type:%s), data left: %d",element_name, element_type,data:len())
  --pos,value,err = parsers.get(element_type)(data)
  pos,value,err = parse(element_type,data)
  if(err ~= nil) then
    dbg_err(err)
    return nil,nil, data, err
  end

  data=data:sub(pos)

  dbg(" Read element value '%s', data left: %d",tostring(value), data:len())
  return element_name, value, data
end

--Reads all elements from binary to BSon
--@param data the data to read from
--@return the resulting table
--@return err an error if any occurred.
local function _elements_to_dict(data)
  local result = {}
  local key, value, err
  while data and data:len() > 0 do
    key, value, data, err = _element_to_dict(data)
    if not key then
      return result, ("Failed to parse element: %s"):format(err)
    end
    dbg("Parsed (%s='%s'), data left : %d", tostring(key),tostring(value), data:len())
    --if type(value) ~= 'table' then value=tostring(value) end
    result[key] = value
  end
  return result
end

--Checks if enough data to parse the result is captured
--@data binary bson data read from socket
--@return true if the full bson table is contained in the data, false if data is incomplete
--@return required size of packet, if known, otherwise nil
function isPacketComplete(data)
  -- First, we check that the header is complete
  if data:len() < 4 then
    local err_msg = "Not enough data in buffer, at least 4 bytes header info expected"
    return false
  end

  local obj_size = string.unpack("<i4", data)

  dbg("BSon packet size is %s", obj_size)

  -- Check that all data is read and the packet is complete
  if data:len() < obj_size then
    return false,obj_size
  end
  return true,obj_size
end

-- Converts bson binary data read from socket into a table
-- of elements
--@param data: binary data
--@return table containing elements
--@return remaining data
--@return error message if not enough data was in packet
function fromBson(data)

  dbg("Decoding, got %s bytes of data", data:len())
  local complete, object_size = isPacketComplete(data)

  if not complete then
    local err_msg = ("Not enough data in buffer, expected %s but only has %d"):format(object_size or "?", data:len())
    dbg(err_msg)
    return {},data, err_msg
  end

  if data:byte(object_size) ~= 0 then
    local err_msg = "Invalid BSON: no null terminator"
    dbg(err_msg)
    return nil, data, err_msg
  end

  local element_portion = data:sub(5,object_size - 1) -- terminator belongs to outer doc
  local remainder = data:sub(object_size+1)
  dbg("element: %s\nremainder: %s", stdnse.tohex(element_portion), stdnse.tohex(remainder))
  local dict, err = _elements_to_dict(element_portion)
  return dict, remainder, err
end


----------------------------------------------------------------------------------
-- Test-code for debugging purposes below
----------------------------------------------------------------------------------
function testBson()
  local p = toBson({hello="world", test="ok"})

  print( "Encoded something ok")
  local orig = fromBson(p)
  print(" Decoded something else ok")
  for i,v in pairs(orig) do
    print(i,v)
  end
end
--testBson()
--------------------------------------------------------------------------------------------------------------
--- END of BSON part
--------------------------------------------------------------------------------------------------------------


--[[ MongoDB wire protocol format

Standard message header :
struct {
    int32   messageLength;  // total size of the message, including the 4 bytes of length
    int32   requestID;      // client or database-generated identifier for this message
    int32   responseTo;     // requestID from the original request (used in responses from db)
    int32   opCode;         // request type - see table below
}

Opcodes :
OP_REPLY         1     Reply to a client request. responseTo is set
OP_MSG           1000  generic msg command followed by a string
OP_UPDATE        2001  update document
OP_INSERT        2002  insert new document
OP_GET_BY_OID    2003  is this used?
OP_QUERY         2004  query a collection
OP_GET_MORE      2005  Get more data from a query. See Cursors
OP_DELETE        2006  Delete documents
OP_KILL_CURSORS  2007  Tell database client is done with a cursor

Query message :
struct {
    MsgHeader header;                 // standard message header
    int32     opts;                   // query options.  See below for details.
    cstring   fullCollectionName;     // "dbname.collectionname"
    int32     numberToSkip;           // number of documents to skip when returning results
    int32     numberToReturn;         // number of documents to return in the first OP_REPLY
    BSON      query ;                 // query object.  See below for details.
  [ BSON      returnFieldSelector; ]  // OPTIONAL : selector indicating the fields to return.  See below for details.
}

For more info about the MongoDB wire protocol, see http://www.mongodb.org/display/DOCS/Mongo+Wire+Protocol

--]]

-- DIY lua-class to create Mongo packets
--@usage call MongoData:new({opCode=MongoData.OP.QUERY}) to create query object
MongoData ={
  uniqueRequestId = 12345,
  -- Opcodes used by Mongo db
  OP = {
    REPLY = 1,
    MSG = 1000,
    UPDATE = 2001,
    INSERT = 2002,
    GET_BY_IOD = 2003,
    QUERY = 2004,
    GET_MORE = 2005,
    DELETE = 2006,
    KILL_CURSORS = 2007,
  },
  -- Lua-DIY constructor
  new = function  (self,o,opCode,responseTo)
    o = o or {}   -- create object if user does not provide one
    setmetatable(o, self) -- DIY inheritance a'la javascript
    self.__index = self
    self.valueString = ''
    self.requestID = MongoData.uniqueRequestId -- Create unique id for message
    MongoData.uniqueRequestId = MongoData.uniqueRequestId +1
    return o
  end
}
--Adds signed int32 to the message body
--@param value the value to add
function MongoData:addInt32(value)
  self.valueString = self.valueString..string.pack("<i4",value)
end
-- Adds a string to the message body
--@param value the string to add
function MongoData:addString(value)
  self.valueString = self.valueString..string.pack('z',value)
end
-- Add a table as a BSon object to the body
--@param dict the table to be converted to BSon
--@return status : true if ok, false if error occurred
--@return Error message if error occurred
function MongoData:addBSON(dict)
  -- status, res = bson.toBson(dict)
  local status, res = toBson(dict)
  if not status then
    dbg(res)
    return status,res
  end

  self.valueString = self.valueString..res
  return true
end
-- Returns the data in this packet in a raw string format to be sent on socket
-- This method creates necessary header information and puts it with the body
function MongoData:data()
  local header = MongoData:new()
  header:addInt32( self.valueString:len()+4+4+4+4)
  header:addInt32( self.requestID)
  header:addInt32( self.responseTo or -1)
  header:addInt32( self.opCode)
  return header.valueString .. self.valueString
end
-- Creates a query
-- @param collectionName string specifying the collection to run query against
-- @param a table containing the query
--@return status : true for OK, false for error
--@return packet data OR error message
local function createQuery(collectionName, query)
  local packet = MongoData:new({opCode=MongoData.OP.QUERY})
  packet:addInt32(0); -- options
  packet:addString(collectionName);
  packet:addInt32(0) -- number to skip
  -- NB: Using value of -1 for "no limit" below is suspect. The protocol
  --     interprets -1 as requesting only one document, not all documents.
  --     https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#wire-op-query
  packet:addInt32(-1) -- number to return : no limit
  local status, error = packet:addBSON(query)

  if not status then
    return status, error
  end

  return true, packet:data()
end
-- Creates a get last error query
-- @param responseTo optional identifier this packet is a response to
--@return status : true for OK, false for error
--@return packet data OR error message
function lastErrorQuery(responseTo)
  local collectionName = "test.$cmd"
  local query = {getlasterror=1}
  return createQuery(collectionName, query)
end
-- Creates a server status query
-- @param responseTo optional identifier this packet is a response to
--@return status : true for OK, false for error
--@return packet data OR error message
function serverStatusQuery(responseTo)
  local collectionName = "test.$cmd"
  local query = {serverStatus = 1}
  return createQuery(collectionName, query)
end
-- Creates a optime query
-- @param responseTo optional identifier this packet is a response to
--@return status : true for OK, false for error
--@return packet data OR error message
function opTimeQuery(responseTo)
  local collectionName = "test.$cmd"
  local query = {getoptime = 1}
  return createQuery(collectionName, query)
end
-- Creates a list databases query
-- @param responseTo optional identifier this packet is a response to
--@return status : true for OK, false for error
--@return packet data OR error message
function listDbQuery(responseTo)
  local collectionName = "admin.$cmd"
  local query = {listDatabases = 1}
  return createQuery(collectionName, query)
end
-- Creates a build info query
-- @param responseTo optional identifier this packet is a response to
--@return status : true for OK, false for error
--@return packet data OR error message
--@return status : true for OK, false for error
--@return packet data OR error message
function buildInfoQuery(responseTo)
  local collectionName = "admin.$cmd"
  local query = {buildinfo = 1}
  return createQuery(collectionName, query)
end
--Reads an int32 from data
--@return int32 value
--@return data unread
local function parseInt32(data)
  local val, pos = string.unpack("<i4", data)
  return val, data:sub(pos)
end
local function parseInt64(data)
  local val, pos =  string.unpack("<i8", data)
  return val, data:sub(pos)
end
-- Parses response header
-- The response header looks like this :
--[[
struct {
    MsgHeader header;                 // standard message header
    int32     responseFlag;           // normally zero, non-zero on query failure
    int64     cursorID;               // id of the cursor created for this query response
    int32     startingFrom;           // indicates where in the cursor this reply is starting
    int32     numberReturned;         // number of documents in the reply
    BSON[]    documents;              // documents
}
--]]
--@param the data from socket
--@return a table containing the header data
local function parseResponseHeader(data)
  local response= {}
  local hdr, rflag, cID, sfrom, nRet, docs

  -- First std message header
  hdr ={}
  hdr["messageLength"], data = parseInt32(data)
  hdr["requestID"], data = parseInt32(data)
  hdr["responseTo"], data = parseInt32(data)
  hdr["opCode"], data = parseInt32(data)
  response["header"] = hdr
  -- Some additional fields
  response["responseFlag"] ,data = parseInt32(data)
  response["cursorID"] ,data = parseInt64(data)
  response["startingFrom"] ,data = parseInt32(data)
  response["numberReturned"] ,data = parseInt32(data)
  response["bson"] = data
  return response
end
--Checks if enough data to parse the result is captured
--@data binary mongodb data read from socket
--@return true if the full mongodb packet is contained in the data, false if data is incomplete
--@return required size of packet, if known, otherwise nil
function isPacketComplete(data)
  -- First, we check that the header is complete
  if data:len() < 4 then
    local err_msg = "Not enough data in buffer, at least 4 bytes header info expected"
    return false
  end

  local obj_size = string.unpack("<i4", data)

  dbg("MongoDb Packet size is %s, (got %d)", obj_size,data:len())

  -- Check that all data is read and the packet is complete
  if data:len() < obj_size then
    return false,obj_size
  end
  return true,obj_size
end

-- Sends a packet over a socket, reads the response
-- and parses it into a table
--@return status : true if ok; false if bad
--@return result : table of status ok, error msg if bad
--@return if status ok : remaining data read from socket but not used
function query(socket, data)
  --Create an error handler
  local catch = function()
    socket:close()
    stdnse.debug1("Query failed")
  end
  local try = nmap.new_try(catch)

  try( socket:send( data ) )

  local data = ""
  local result =  {}
  local err_msg
  local isComplete, pSize
  while not isComplete do
    dbg("mongo: waiting for data from socket, got %d bytes so far...",data:len())
    data = data .. try( socket:receive() )
    isComplete, pSize = isPacketComplete(data)
  end
  -- All required data should be read now
  local packetData = data:sub(1,pSize)
  local residualData = data:sub(pSize+1)
  local responseHeader = parseResponseHeader(packetData)

  if responseHeader["responseFlag"] ~= 0 then
    dbg("Response flag not zero : %d, some error occurred", responseHeader["responseFlag"])
  end

  local bsonData = responseHeader["bson"]
  if #bsonData == 0 then
    dbg("No BSon data returned ")
    return false, "No Bson data returned"
  end

  -- result, data, err_msg = bson.fromBson(bsonData)
  result, data, err_msg = fromBson(bsonData)

  if err_msg then
    dbg("Got error converting from bson: %s" , err_msg)
    return false, ("Got error converting from bson: %s"):format(err_msg)
  end
  return true,result, residualData
end

function login(socket, db, username, password)

  local collectionName = ("%s.$cmd"):format(arg_DB or db)
  local q = { getnonce = 1 }
  local status, packet = createQuery(collectionName, q)
  local response
  status, response = query(socket, packet)
  if ( not(status) or not(response.nonce) ) then
    return false, "Failed to retrieve nonce"
  end

  local nonce = response.nonce
  local pwdigest = stdnse.tohex(openssl.md5(username .. ':mongo:' ..password))
  local digest = stdnse.tohex(openssl.md5(nonce .. username .. pwdigest))

  q = { user = username, nonce = nonce, key = digest }
  q._cmd = { authenticate = 1 }

  local status, packet = createQuery(collectionName, q)
  status, response = query(socket, packet)
  if ( not(status) ) then
    return status, response
  elseif ( response.errmsg == "auth fails" ) then
    return false, "Authentication failed"
  elseif ( response.errmsg ) then
    return false, response.errmsg
  end
  return status, response
end


--- Converts a query result as received from MongoDB query into nmap "result" table
-- @param resultTable table as returned from a query
-- @return table suitable for <code>stdnse.format_output</code>
function queryResultToTable( resultTable )

  local result = {}
  for k,v in pairs( resultTable ) do
    if type(v) == 'table' then
      table.insert(result,k)
      table.insert(result,queryResultToTable(v))
    else
      table.insert(result,(("%s = %s"):format(tostring(k), tostring(v))))
    end
  end
  return result

end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end

-- https://github.com/mongodb/mongo-python-driver/blob/master/test/bson_corpus/
local TESTS = {
  -- 0x01 = BSONNUM, float
  { desc = "BSONNUM: +1.0",
    bson = "10000000016400000000000000F03F00",
    obj = {d = {1.0}}
  },
  { desc = "BSONNUM: -1.0",
    bson = "10000000016400000000000000F0BF00",
    obj = {d = {-1.0}}
  },
  { desc = "BSONNUM: +1.0001220703125",
    bson = "10000000016400000000008000F03F00",
    obj = {d = {1.0001220703125}}
  },
  { desc = "BSONNUM: -1.0001220703125",
    bson = "10000000016400000000008000F0BF00",
    obj = {d = {-1.0001220703125}}
  },
  { desc = "BSONNUM: 1.2345678921232E+18",
    bson = "100000000164002a1bf5f41022b14300",
    obj = {d = {1.2345678921232e18}}
  },
  { desc = "BSONNUM: -1.2345678921232E+18",
    bson = "100000000164002a1bf5f41022b1c300",
    obj = {d = {-1.2345678921232e18}}
  },
  { desc = "BSONNUM: 0.0",
    bson = "10000000016400000000000000000000",
    obj = {d = {0.0}}
  },
  { desc = "BSONNUM: -0.0",
    bson = "10000000016400000000000000008000",
    obj = {d = {-0.0}}
  },
  -- Lua 5.3 safely round-trips all of these floats!
  { desc = "BSONNUM: NaN",
    bson = "10000000016400000000000000F87F00",
    test = function(o) return tostring(o.d) == "nan" end
  },
  { desc = "BSONNUM: NaN with payload",
    bson = "10000000016400120000000000F87F00",
    test = function(o) return tostring(o.d) == "nan" end
  },
  { desc = "BSONNUM: Inf",
    bson = "10000000016400000000000000F07F00",
    test = function(o) return tostring(o.d) == "inf" end
  },
  { desc = "BSONNUM: -Inf",
    bson = "10000000016400000000000000F0FF00",
    test = function(o) return tostring(o.d) == "-inf" end
  },
  { desc = "bad BSONNUM: double truncated", invalid = true,
    bson = "0B0000000164000000F03F00"
  },
  -- 0x02 = BSONSTR, string
  { desc = "BSONSTR: Empty string", bson = "0D000000026100010000000000",
    obj = {a = ""}
  },
  { desc = "BSONSTR: Single character", bson = "0E00000002610002000000620000",
    obj = {a = "b"}
  },
  { desc = "BSONSTR: Multi-character",
    bson = "190000000261000D0000006162616261626162616261620000",
    obj = {a = "abababababab"}
  },
  { desc = "BSONSTR: Embedded nulls",
    bson = "190000000261000D0000006162006261620062616261620000",
    obj = {a = "ab\x00bab\x00babab"}
  },
  { desc = "BSONSTR: bad string length: 0 (but no 0x00 either)", invalid = true,
    bson = "0C0000000261000000000000"
  },
  { desc = "BSONSTR: bad string length: -1", invalid = true,
    bson = "0C000000026100FFFFFFFF00"
  },
  { desc = "BSONSTR: bad string length: eats terminator", invalid = true,
    bson = "10000000026100050000006200620000"
  },
  { desc = "BSONSTR: bad string length: longer than rest of document", invalid = true,
    bson = "120000000200FFFFFF00666F6F6261720000"
  },
  { desc = "BSONSTR: string is not null-terminated", invalid = true,
    bson = "1000000002610004000000616263FF00"
  },
  { desc = "BSONSTR: empty string, but extra null", invalid = true,
    bson = "0E00000002610001000000000000"
  },
  { desc = "Empty array", bson = "0D000000046100050000000000",
    -- Should probably use json.make_array and json.typeof for this.
    FAIL = "Can't distinguish array vs object table",
    obj = {a = {}}
  },
  { desc = "single element array", bson = "140000000461000C0000001030000A0000000000",
    FAIL = "Can't distinguish array vs object table",
    obj = {a = {10}}
  },
  { desc = "single element with empty index",
    bson = "130000000461000B00000010000A0000000000",
    fixed = "140000000461000C0000001030000A0000000000",
    FAIL = "Can't distinguish array vs object table",
    obj = {a = {10}}
  },
  { desc = "bad array: too long", invalid = true,
    bson = "140000000461000D0000001030000A0000000000",
  },
  { desc = "bad array: too short", invalid = true,
    bson = "140000000461000B0000001030000A0000000000"
  },
  { desc = "bad array: bad string length", invalid = true,
    bson = "1A00000004666F6F00100000000230000500000062617A000000"
  },
  { desc = "BSONBIN: subtype 0x00 (Zero-length)", bson = "0D000000057800000000000000",
    FAIL = "No encoder for BSONBIN type",
    obj = {x = "Binary subtype 0: "}
  },
  { desc = "BSONBIN: subtype 0x00", bson = "0F0000000578000200000000FFFF00",
    FAIL = "No encoder for BSONBIN type",
    obj = {x = "Binary subtype 0: ffff"}
  },
  { desc = "BSONBIN: subtype 0x01", bson = "0F0000000578000200000001FFFF00",
    FAIL = "No encoder for BSONBIN type",
    obj = {x = "Binary subtype 1: ffff"}
  },
  { desc = "BSONBIN: subtype 0x03",
    bson = "1D000000057800100000000373FFD26444B34C6990E8E7D1DFC035D400",
    FAIL = "No encoder for BSONBIN type",
    obj = {x = "Binary subtype 3: 73ffd26444b34c6990e8e7d1dfc035d4"}
  },
  { desc = "BSONBIN: Length longer than document", invalid = true,
    bson = "1D000000057800FF0000000573FFD26444B34C6990E8E7D1DFC035D400"
  },
  { desc = "BSONBIN: Negative length", invalid = true,
    bson = "0D000000057800FFFFFFFF0000"
  },
  { desc = "BSONBIN: subtype 0x02 length too long ", invalid = true,
    bson = "13000000057800060000000203000000FFFF00"
  },
  { desc = "BSONBIN: subtype 0x02 length too short", invalid = true,
    bson = "13000000057800060000000201000000FFFF00"
  },
  { desc = "BSONBIN: subtype 0x02 length negative one", invalid = true,
    bson = "130000000578000600000002FFFFFFFFFFFF00"
  },
  { desc = "Int32 MinValue", bson = "0C0000001069000000008000",
    obj = {i = -2147483648}
  },
  { desc = "Int32: MaxValue", bson = "0C000000106900FFFFFF7F00",
    obj = {i = 2147483647}
  },
  { desc = "Int32: -1", bson = "0C000000106900FFFFFFFF00",
    obj = {i = -1}
  },
  { desc = "Int32: 0", bson = "0C0000001069000000000000",
    obj = {i = 0}
  },
  { desc = "Int32: 1", bson = "0C0000001069000100000000",
    obj = {i = 1}
  },
  { desc = "Int32: Bad int32 field length", invalid = true,
    bson = "090000001061000500"
  }
}
test_suite = unittest.TestSuite:new()

local equal = unittest.equal
local is_nil = unittest.is_nil
local is_true = unittest.is_true
local type_is = unittest.type_is

for _, test in ipairs(TESTS) do
  dbg("Loading test %s...", test.desc)
  local fmt = function(description)
    return ("%s: %s"):format(test.desc, description)
  end

  local binary = stdnse.fromhex(test.bson)
  local obj, rem, err = fromBson(binary)
  if test.invalid then
    dbg("Expect error, type is %s: %s", type(err), err)
    test_suite:add_test(type_is("string", err), fmt("Error reported for invalid BSON"))
  else
    test_suite:add_test(type_is("table", obj), fmt("BSON parsed to table"))
    test_suite:add_test(is_nil(err), fmt("No error reported for valid BSON"))

    local status, bsonout = toBson(obj)
    test_suite:add_test(is_true(status), fmt("toBson succeeds"))
    test_suite:add_test(equal(type(bsonout), "string"), fmt("toBson returns string"))

    -- round-trip test. Some "bad" encodings are ok but will generate different bson
    local rttest = equal(stdnse.tohex(bsonout), test.fixed and test.fixed or stdnse.tohex(binary))
    -- Our library is incomplete in some ways as noted in FAIL
    if test.FAIL then
      rttest = unittest.expected_failure(rttest)
    end
    test_suite:add_test(rttest, fmt("Round-trip encoding matches"))
    if test.test then
      test_suite:add_test(is_true(test.test(obj)), fmt("Extra test"))
    end
  end
end
return _ENV;
