---
-- Library methods for handling MongoDB, creating and parsing packets.
--
-- @author Martin Holst Swende
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @args mongodb.db - the database to use for authentication

-- Created 01/13/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Revised 01/03/2012 - v0.2 - added authentication support <patrik@cqure.net>

local bin = require "bin"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
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
--local dbg =stdnse.debug1

local err =stdnse.debug1

----------------------------------------------------------------------
-- First of all comes a Bson parsing library. This can easily be moved out into a separate library should other
-- services start to use Bson
----------------------------------------------------------------------
-- Library methods for handling the BSON format
--
-- For more documentation about the BSON format,
---and more details about its implementations, check out the
-- python BSON implementation which is available at
-- http://github.com/mongodb/mongo-python-driver/blob/master/pymongo/bson.py
-- and licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0)
--
-- @author Martin Holst Swende
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Version 0.1

-- Created 01/13/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
--module("bson", package.seeall)
--require("bin")
local function dbg_err(str,...)
  stdnse.debug1("Bson-ERR:"..str, ...)
end
--local err =stdnse.log_error

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
    return false, ("key %r must not contain '.'"):format(tostring(key))
  end

  local name =bin.pack("z",key) -- null-terminated string
  if type(value) == 'string' then
    local cstring = bin.pack("z",value) -- null-terminated string
    local length = bin.pack("<i", cstring:len())
    local op = "\x02"
    return true, op .. name .. length .. cstring
  elseif type(value) =='table' then
    return true, "\x02" .. name .. toBson(value)
  elseif type(value)== 'boolean' then
    return true, "\x08" .. name .. (value and '\x01' or '\0')
  elseif type(value) == 'number' then
    --return "\x10" .. name .. bin.pack("<i", value)
    -- Use 01 - double for - works better than 10
    return true, '\x01' .. name .. bin.pack("<d", value)
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
  return true, bin.pack("<I", length) .. elements .. "\0"
end

-- Reads a null-terminated string. If length is supplied, it is just cut
-- out from the data, otherwise the data is scanned for at null-char.
--@param data the data which starts with a c-string
--@param length optional length of the string
--@return the string
--@return the remaining data (*without* null-char)
local function get_c_string(data,length)
  if not length then
    local index = data:find('\0')
    if index == nil then
      error({code="C-string did not contain NULL char"})
    end
    length = index
  end
  local value = data:sub(1,length-1)

  --dbg("Found char at pos %d, data is %s c-string is %s",length, data, value)

  return value, data:sub(length+1)
end

-- Element parser. Parse data elements
-- @param data String containing binary data
-- @return Position in the data string where parsing stopped
-- @return Unpacked value
-- @return error string if error occurred
local function parse(code,data)
  if 1 == code  then -- double
    return bin.unpack("<d", data)
  elseif 2 == code then -- string
    -- data length = first four bytes
    local _,len = bin.unpack("<i",data)
    -- string data = data[5] -->
    local value = get_c_string(data:sub(5), len)
    -- Count position as header (=4) + length of string (=len)+ null char (=1)
    return 4+len+1,value
  elseif 3 == code or 4 == code then -- table or array
    local object, err

    -- Need to know the length, to return later
    local _,obj_size = bin.unpack("<i", data)
    -- Now, get the data object
    dbg("Recursing into bson array")
    object, data, err = fromBson(data)
    dbg("Recurse finished, got data object")
    -- And return where the parsing stopped
    return obj_size+1, object
    --6 = _get_null
    --7 = _get_oid
  elseif 8 == code then -- Boolean
    return 2, data:byte(1) == 1
  elseif 9 == code then -- int64, UTC datetime
    return bin.unpack("<l", data)
  elseif 10 == code then -- nullvalue
    return 0,nil
    --11= _get_regex
    --12= _get_ref
    --13= _get_string, # code
    --14= _get_string, # symbol
    --15=  _get_code_w_scope
  elseif 16 == code then -- 4 byte integer
    return bin.unpack("<i", data)
    --17= _get_timestamp
  elseif 18 == code then -- long
    return bin.unpack("<l", data)
  end
  local err = ("Getter for %d not implemented"):format(code)
  return 0, data, err
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
local function _elements_to_dict(data)
  local result = {}
  local key,value
  while data and data:len() > 1 do
    key, value, data = _element_to_dict(data)
    dbg("Parsed (%s='%s'), data left : %d", tostring(key),tostring(value), data:len())
    if type(value) ~= 'table' then value=tostring(value) end
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

  local _,obj_size = bin.unpack("<i", data)

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

  local element_portion = data:sub(5,object_size)
  local remainder = data:sub(object_size+1)
  return _elements_to_dict(element_portion), remainder
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
--Adds unsigned int32 to the message body
--@param value the value to add
function MongoData:addUnsignedInt32(value)
  self.valueString = self.valueString..bin.pack("<I",value)
end
-- Adds a string to the message body
--@param value the string to add
function MongoData:addString(value)
  self.valueString = self.valueString..bin.pack('z',value)
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
  header:addUnsignedInt32( self.valueString:len()+4+4+4+4)
  header:addUnsignedInt32( self.requestID)
  header:addUnsignedInt32( self.responseTo or 0xFFFFFFFF)
  header:addUnsignedInt32( self.opCode)
  return header.valueString .. self.valueString
end
-- Creates a query
-- @param collectionName string specifying the collection to run query against
-- @param a table containing the query
--@return status : true for OK, false for error
--@return packet data OR error message
local function createQuery(collectionName, query)
  local packet = MongoData:new({opCode=MongoData.OP.QUERY})
  packet:addUnsignedInt32(0); -- options
  packet:addString(collectionName);
  packet:addUnsignedInt32(0) -- number to skip
  packet:addUnsignedInt32(-1) -- number to return : no limit
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
  local pos,val = bin.unpack("<i",data)
  return val, data:sub(pos)
end
local function parseInt64(data)
  local pos,val =  bin.unpack("<l",data)
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

  local _,obj_size = bin.unpack("<i", data)

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

return _ENV;
