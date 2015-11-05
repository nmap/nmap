--- Library method for communicating over RMI (JRMP + java serialization)
--
-- This is a not complete RMI implementation for Lua, which is meant to be able
-- to invoke methods and parse returnvalues which are simple, basically the java primitives.
-- This can be used to e.g dump out the registry, and perform authentication against
-- e.g JMX-services.
--
-- This library also contains some classes which works pretty much like the
-- java classes BufferedReader, BufferedWriter, DataOutputStream and DataInputStream.
--
-- Most of the methods in the RMIDataStream class is based on the OpenJDK RMI Implementation,
-- and I have kept the methodnames  as they are in java, so it should not be too hard to find
-- the corresponding functionality in the jdk codebase to see how things 'should' be done, in case
-- there are bugs or someone wants to make additions. I have only implemented the
-- things that were needed to get things working, but it should be pretty simple to add more
-- functionality by lifting over more stuff from the jdk.
--
-- The interesting classes in OpenJDK are:
--  java.io.ObjectStreamConstants
--  java.io.ObjectStreamClass
--  java.io.ObjectInputStream
--  sun.rmi.transport.StreamRemoteCall
-- and a few more.
--
-- If you want to add calls to classes you know of, you can use e.g Jode to decompile the
-- stub-class or skeleton class and find out the details that are needed to perform an
-- RMI method invocation. Those are
--  Class hashcode
--  Method number (each method gets a number)
--  Arguments f
-- You also need the object id (so the remote server knows what instance you are talking to). That can be
-- fetched from the registry (afaik) but not currently implemented. Some object ids are static : the registry is always 0
--
-- @author Martin Holst Swende
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @see java 1.4 RMI-spec: http://java.sun.com/j2se/1.4.2/docs/guide/rmi/
-- @see java 5 RMI-spec: http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmiTOC.html
-- @see java 6 RMI-spec : http://java.sun.com/javase/6/docs/technotes/guides/rmi/index.html
-- @see The protocol for Java object serializtion : http://java.sun.com/javase/6/docs/platform/serialization/spec/protocol.html
-- Version 0.2

-- Created 09/06/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Fixed more documentation - v0.2 Martin Holst Swende <martin@swende.se>

local bin = require "bin"
local bit = require "bit"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("rmi", stdnse.seeall)
-- Some lazy shortcuts

local function dbg(str,...)
  local arg={...}
  stdnse.debug3("RMI:"..str, table.unpack(arg))
end
-- Convenience function to both print an error message and return <false, msg>
-- Example usage :
-- if foo ~= "gazonk" then
--   return doh("Foo should be gazonk but was %s", foo)
-- end
local function doh(str,...)
  local arg={...}
  stdnse.debug1("RMI-ERR:"..tostring(str), table.unpack(arg))
  return false, str
end

---
-- BufferedWriter
-- This buffering writer provide functionality much like javas BufferedWriter.
--
-- BufferedWriter wraps the pack-functionality from bin, and buffers data internally
-- until flush is called. When flush is called, it either sends the data to the socket OR
-- returns the data, if no socket has been set.
--@usage:
-- local bWriter = BufferedWriter:new(socket)
-- local breader= BufferedReader:new(socket)
--
-- bWriter.pack('>i', integer)
-- bWriter.flush() -- sends the data
--
-- if bsocket:canRead(4) then -- Waits until four bytes can be read
--   local packetLength = bsocket:unpack('i') -- Read the four bytess
--   if bsocket:canRead(packetLength) then
--     -- ...continue reading packet values

BufferedWriter = {
  new = function(self, socket)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.writeBuffer = ''
    o.pos = 1
    o.socket = socket
    return o
  end,

  -- Sends data over the socket
  -- (Actually, just buffers until flushed)
  -- @return Status (true or false).
  -- @return Error code (if status is false).
  send = function( self, data )
    self.writeBuffer = self.writeBuffer .. data
  end,
  -- Convenience function, wraps bin
  pack = function(self, fmt, ... )
    local arg={...}
    self.writeBuffer = self.writeBuffer .. bin.pack( fmt, table.unpack(arg))
  end,

  -- This function flushes the buffer contents, thereby emptying
  -- the buffer. If a socket has been supplied, that's where it will be sent
  -- otherwise the buffer contents are returned
  --@return status
  --@return content of buffer, in case no socket was used
  flush = function(self)

    local content = self.writeBuffer
    self.writeBuffer = ''

    if not self.socket then
      return true, content
    end
    return self.socket:send(content)
  end,

}
---
-- BufferedReader reads data from the supplied socket and contains functionality
-- to read all that is available and store all that is not currently needed, so the caller
-- gets an exact number of bytes (which is not the case with the basic nmap socket implementation)
-- If not enough data is available, it blocks until data is received, thereby handling the case
-- if data is spread over several tcp packets (which is a pitfall for many scripts)
--
-- It wraps unpack from bin for the reading.
-- OBS! You need to check before invoking skip or unpack that there is enough
-- data to read. Since this class does not parse arguments to unpack, it does not
-- know how much data to read ahead on those calls.
--@usage:
-- local bWriter = BufferedWriter:new(socket)
-- local breader= BufferedReader:new(socket)
--
-- bWriter.pack('>i', integer)
-- bWriter.flush() -- sends the data
--
-- if bsocket:canRead(4) then -- Waits until four bytes can be read
--   local packetLength = bsocket:unpack('i') -- Read the four bytess
--   if bsocket:canRead(packetLength) then
--     -- ...continue reading packet values

BufferedReader = {
  new = function(self, socket, readBuffer)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.readBuffer = readBuffer -- May be nil
    o.pos = 1
    o.socket = socket -- May also be nil
    return o
  end,
  ---
  -- This method blocks until the specified number of bytes
  -- have been read from the socket and are available for
  -- the caller to read, e.g via the unpack function
  canRead= function(self,count)
    local status, data
    self.readBuffer = self.readBuffer or ""
    local missing = self.pos + count - #self.readBuffer -1
    if ( missing > 0) then
      if self.socket == nil then
        return doh("Not enough data in static buffer")
      end

      status, data = self.socket:receive_bytes( missing )
      if ( not(status) ) then
        return false, data
      end
      self.readBuffer = self.readBuffer .. data
    end
    -- Now and then, we flush the buffer
    if ( self.pos > 1024) then
      self.readBuffer = self.readBuffer:sub( self.pos )
      self.pos = 1
    end
    return true
  end,
  ---
  --@return Returns the number of bytes already available for reading
  bufferSize = function(self)
    return #self.readBuffer +1 -self.pos
  end,
  ---
  -- This function works just like bin.unpack (in fact, it is
  -- merely a wrapper around it.  However, it uses the data
  -- already read into the buffer, and the internal position
  --@param format - see bin
  --@return the unpacked value (NOT the index)
  unpack = function(self,format)
    local ret = {bin.unpack(format, self.readBuffer, self.pos)}
    self.pos = ret[1]
    return table.unpack(ret,2)
  end,
  ---
  -- This function works just like bin.unpack (in fact, it is
  -- merely a wrapper around it.  However, it uses the data
  -- already read into the buffer, and the internal position.
  -- This method does not update the current position, and the
  -- data can be read again
  --@param format - see bin
  --@return the unpacked value (NOT the index)
  peekUnpack = function(self,format)
    local ret = {bin.unpack(format, self.readBuffer, self.pos)}
    return table.unpack(ret,2)
  end,
  ---
  -- Tries to read a byte, without consuming it.
  --@return status
  --@return bytevalue
  peekByte = function(self)
    if self:canRead(1) then
      return true, self:peekUnpack('C')
    end
    return false
  end,
  ---
  -- Skips a number of bytes
  --@param len the number of bytes to skip
  skip = function(self, len)
    if(#self.readBuffer < len + self.pos) then
      return doh("ERROR: reading too far ahead")
    end
    local skipped = self.readBuffer:sub(self.pos, self.pos+len-1)
    self.pos = self.pos + len
    return true, skipped
  end,

}

-- The classes are generated when this file is loaded, by the definitions in the JavaTypes
-- table. That table contains mappings between the format used by bin and the types
-- available in java, aswell as the lengths (used for availability-checks) and the name which
-- is prefixed by read* or write* when monkey-patching the classes and adding functions.
-- For example: {name = 'Int', expr = '>i', len=  4}, will generate the functions
-- writeInt(self, value) and readInt() respectively

local JavaTypes = {
  {name = 'Int', expr = '>i', len=  4},
  {name = 'UnsignedInt', expr = '>I', len=  4},
  {name = 'Short', expr = '>s', len=  2},
  {name = 'UnsignedShort', expr = '>S', len=  2},
  {name = 'Long', expr = '>l', len=  8},
  {name = 'UnsignedLong', expr = '>L', len=  8},
  {name = 'Byte', expr = '>C', len=  1},
}

---
-- The JavaDOS classes
-- The JavaDOS class is an approximation of a java DataOutputStream. It provides convenience functions
-- for writing java types to an underlying BufferedWriter
--
-- When used in conjunction with the BufferedX- classes, they handle the availability-
-- checks transparently, i.e the caller does not have to check if enough data is available
--
-- @usage:
-- local dos = JavaDOS:new(BufferedWriter:new(socket))
-- local dos = JavaDIS:new(BufferedReader:new(socket))
-- dos:writeUTF("Hello world")
-- dos:writeInt(3)
-- dos:writeLong(3)
-- dos:flush() -- send data
-- local answer = dis:readUTF()
-- local int = dis:readInt()
-- local long = dis:readLong()

JavaDOS = {
  new = function  (self,bWriter)
    local o = {}   -- create new object if user does not provide one
    setmetatable(o, self)
    self.__index = self -- DIY inheritance
    o.bWriter = bWriter
    return o
  end,
  -- This closure method generates all writer methods on the fly
  -- according to the definitions in JavaTypes
  _generateWriterFunc = function(self, javatype)
    local functionName = 'write'..javatype.name
    local newFunc = function(_self, value)
      --dbg(functionName .."(%s) called" ,tostring(value))
      return _self:pack(javatype.expr, value)
    end
    self[functionName] = newFunc
  end,

  writeUTF = function(self, text)
    -- TODO: Make utf-8 of it
    return self:pack('>P', text)
  end,
  pack = function(self, ...)
    local arg={...}
    return self.bWriter:pack(table.unpack(arg))
  end,
  write = function(self, data)
    return self.bWriter:send(data)
  end,
  flush = function(self)
    return self.bWriter:flush()
  end,
}

---
-- The JavaDIS class
-- JavaDIS is close to java DataInputStream. It provides convenience functions
-- for reading java types from an underlying BufferedReader
--
-- When used in conjunction with the BufferedX- classes, they handle the availability-
-- checks transparently, i.e the caller does not have to check if enough data is available
--
-- @usage:
-- local dos = JavaDOS:new(BufferedWriter:new(socket))
-- local dos = JavaDIS:new(BufferedReader:new(socket))
-- dos:writeUTF("Hello world")
-- dos:writeInt(3)
-- dos:writeLong(3)
-- dos:flush() -- send data
-- local answer = dis:readUTF()
-- local int = dis:readInt()
-- local long = dis:readLong()
JavaDIS = {
  new = function  (self,bReader)
    local o = {}   -- create new object if user does not provide one
    setmetatable(o, self)
    self.__index = self -- DIY inheritance
    o.bReader = bReader
    return o
  end,

  -- This closure method generates all reader methods (except nonstandard ones) on the fly
  -- according to the definitions in JavaTypes.
  _generateReaderFunc = function(self, javatype)
    local functionName = 'read'..javatype.name
    local newFunc = function(_self)
      --dbg(functionName .."() called" )
      if not _self.bReader:canRead(javatype.len)  then
        local err = ("Not enough data in buffer (%d required by %s)"):format(javatype.len, functionName)
        return doh(err)
      end
      return true, _self.bReader:unpack(javatype.expr)
    end
    self[functionName] = newFunc
  end,
  -- This is a bit special, since we do not know beforehand how many bytes must be read. Therefore
  -- this cannot be generated on the fly like the others.
  readUTF = function(self, text)
    -- First, we need to read the length, 2 bytes
    if not self.bReader:canRead(2)  then-- Length of the string is two bytes
      return false, "Not enough data in buffer [0]"
    end
    -- We do it as a 'peek', so bin can reuse the data to unpack with 'P'
    local len = self.bReader:peekUnpack('>S')
    --dbg("Reading utf, len %d" , len)
    -- Check that we have data
    if not self.bReader:canRead(len) then
      return false, "Not enough data in buffer [1]"
    end
    -- For some reason, the 'P' switch does not work for me.
    -- Probably some idiot thing. This is a hack:
    local val = self.bReader.readBuffer:sub(self.bReader.pos+2, self.bReader.pos+len+2-1)
    self.bReader.pos = self.bReader.pos+len+2
    -- Someone smarter than me can maybe get this working instead:
    --local val = self.bReader:unpack('P')
    --dbg("Read UTF: %s", val)
    return true, val
  end,
  readLongAsHexString = function(self)
    if not self.bReader:canRead(8)  then-- Length of the string is two bytes
      return false, "Not enough data in buffer [3]"
    end
    return true, self.bReader:unpack('H8')

  end,
  skip = function(self, len)
    return self.bReader:skip(len)
  end,
  canRead = function(self, len)
    return self.bReader:canRead(len)
  end,
}

-- Generate writer-functions on the JavaDOS/JavaDIS classes on the fly
for _,x in ipairs(JavaTypes) do
  JavaDOS._generateWriterFunc(JavaDOS, x)
  JavaDIS._generateReaderFunc(JavaDIS, x)
end
---
-- This class represents a java class and is what is returned by the library
-- when invoking a remote function. Therefore, this can also represent a java
-- object instance.
JavaClass = {
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  customDataFormatter  = nil,

  setName = function( self, name )
    dbg("Setting class name to %s", name)
    self.name = name
  end,
  setSerialID = function( self, serial ) self.serial = serial end,
  setFlags = function( self, flags )
    self.flags = RMIUtils.flagsToString(flags)
    self._binaryflags = flags
  end,

  isExternalizable = function(self)
    if self._binaryFlags == nil then return false end

    return bit.band(self._binaryflags, RMIUtils.SC_EXTERNALIZABLE)
  end,

  addField = function( self, field )
    if self.fields == nil then self.fields = {} end
    table.insert( self.fields, field )
    --self[field.name] = field
  end,
  setSuperClass = function(self,super) self.superClass = super end,

  setCustomData = function(self, data) self.customData = data end,
  getCustomData = function(self) return self.customData end,

  setInterfaces = function(self,ifaces) self.ifaces = ifaces end,
  getName = function( self ) return self.name end,
  getSuperClass = function(self) return self.superClass end,
  getSerialID = function( self ) return self.serial end,
  getFlags = function( self ) return self.flags end,
  getFields = function( self ) return self.fields end,
  getFieldByName = function( self, name )
    if self.fields == nil then return end
    for i=1, #self.fields do
      if ( self.fields[i].name == name ) then
        return self.fields[i]
      end
    end
  end,

  __tostring = function( self )
    local data = {}
    if self.name ~=nil then
      data[#data+1] = ("%s "):format(self.name)
    else
      data[#data+1] = "???"
    end
    if  self.superClass~=nil then
      data[#data+1] = " extends ".. tostring( self.superClass)
    end
    if self.ifaces ~= nil then
      data[#data+1] = " implements " ..  self.ifaces
    end
    if self.fields ~=nil then
      for i=1, #self.fields do
        if i == 1 then
          data[#data+1] = "["
        end
        data[#data+1] = tostring(self.fields[i])
        if ( i < #self.fields ) then
          data[#data+1] = ";"
        else
          data[#data+1] = "]"
        end

      end
    end
    return table.concat(data)
  end,
  toTable = function(self, customDataFormatter)
    local data = {self.name}

    if self.externalData ~=nil then
      table.insert(data, tostring(self.externalData))
    end

    --if self.name ~=nil then
    --  data.class = self.name
    --end
    if self.ifaces ~= nil then
      table.insert(data, " implements " .. self.ifaces)
    end

    if  self.superClass~=nil then
      local extends = self.superClass:toTable()
      table.insert(data ,"extends")
      table.insert(data, extends)
      --data.extends = self.superClass:toTable()
    end
    if self.fields ~=nil then
      table.insert(data, "fields")
      local f = {}
      for i=1, #self.fields do
        table.insert(f, self.fields[i]:toTable())
      end
      table.insert(data, f)
    end

    if self.customData ~=nil then
      local formatter =  JavaClass['customDataFormatter']
      if formatter ~= nil then
        local title, cdata = formatter(self.name, self.customData)
        table.insert(data, title)
        table.insert(data, cdata)
      else
        table.insert(data, "Custom data")
        table.insert(data, self.customData)
      end
    end

    return data

  end,

}
--- Represents a field in an object, i.e an object member
JavaField = {

  new = function(self, name, typ )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.name = name
    o.type = typ
    return o
  end,

  setType = function( self, typ ) self.type = typ end,
  setSignature = function( self, sig ) self.signature = sig end,
  setName = function( self, name ) self.name = name end,
  setObjectType = function( self, ot ) self.object_type = ot end,
  setReference = function( self, ref ) self.ref = ref end,
  setValue = function (self, val)
    dbg("Setting field value to %s", tostring(val))
    self.value = val

  end,

  getType = function( self ) return self.type end,
  getSignature = function( self ) return self.signature end,
  getName  = function( self ) return self.name end,
  getObjectType = function( self ) return self.object_type end,
  getReference = function( self ) return self.ref end,
  getValue = function( self ) return self.value end,

  __tostring = function( self )
    if self.value ~= nil then
      return string.format("%s %s = %s", self.type, self.name, self.value)
    else
      return string.format("%s %s", self.type, self.name)
    end
  end,
  toTable = function(self)
    local data = {tostring(self.type) .. " " .. tostring(self.name)}
    --print("FIELD VALUE:", self.value)
    if self.value ~= nil then
      if type(self.value) == 'table' then
        if self.value.toTable ~=nil then
          table.insert(data, self.value:toTable())
        else
          table.insert(data, self.value)
        end
      else
        table.insert(data, self.value)
      end
    end
    return data
  end,

}
---
-- Represents a java array. Internally, this is a lua list of JavaClass-instances
JavaArray = {
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.values = {}
    return o
  end,
  setClass = function( self, class ) self.class = class end,
  setLength = function( self, length ) self.length = length end,
  setValue = function(self, index, object) self.values[index] = object end,
  __tostring=function(self)
    local data = {
      ("Array: %s [%d] = {"):format(tostring(self.class), self.length)
    }

    for i=1, #self.values do
      data[#data+1] = self.values[i]..","
    end
    data[#data+1] = "}"
    return table.concat(data)
  end,
  toTable = function(self)
    local title = ("Array: %s [%d] = {"):format(tostring(self.class), self.length)
    local t =  {title = self.values}
    return t
  end,

  getValues = function(self) return self.values end
}





TC = {
  TC_NULL = 0x70,
  TC_REFERENCE = 0x71,
  TC_CLASSDESC = 0x72,
  TC_OBJECT = 0x73,
  TC_STRING = 0x74,
  TC_ARRAY = 0x75,
  TC_CLASS = 0x76,
  TC_BLOCKDATA = 0x77,
  TC_ENDBLOCKDATA = 0x78,
  TC_RESET = 0x79,
  TC_BLOCKDATALONG = 0x7A,
  TC_EXCEPTION = 0x7B,
  TC_LONGSTRING =  0x7C,
  TC_PROXYCLASSDESC =  0x7D,
  TC_ENUM =  0x7E,

  Integer = 0x49,
  Object = 0x4c,

  Strings = {
    [0x49] = "Integer",
    [0x4c] = "Object",
    [0x71] = "TC_REFERENCE",
    [0x70] = "TC_NULL",
    [0x71] = "TC_REFERENCE",
    [0x72] = "TC_CLASSDESC",
    [0x73] = "TC_OBJECT",
    [0x74] = "TC_STRING",
    [0x75] = "TC_ARRAY",
    [0x76] = "TC_CLASS",
    [0x77] = "TC_BLOCKDATA",
    [0x78] = "TC_ENDBLOCKDATA",
    [0x79] = "TC_RESET",
    [0x7A] = "TC_BLOCKDATALONG",
    [0x7B] = "TC_EXCEPTION",
    [0x7C] = "TC_LONGSTRING",
    [0x7D] = "TC_PROXYCLASSDESC",
    [0x7E] = "TC_ENUM",
  },

}

local Version= 0x02
local Proto= {Stream=0x4b, SingleOp=0x4c, Multiplex=0x4d}

---
-- RmiDataStream class
-- This class can handle reading and writing JRMP, i.e RMI wire protocol and
-- can do some very limited java deserialization. This implementation has
-- borrowed from OpenJDK RMI implementation, but only implements an
-- absolute minimum of what is required in order to perform some basic calls
--

RmiDataStream = {
  new = function  (self,o)
    o = o or {}   -- create object if user does not provide one
    setmetatable(o, self)
    self.__index = self -- DIY inheritance
    return o
  end,
}
-- An output stream in RMI consists of transport Header information followed by a sequence of Messages.
--  Out:
--    Header Messages
--    HttpMessage
--  Header:
--    0x4a 0x52 0x4d 0x49 Version Protocol
-- (4a 52 4d 49 === JRMI)
--  Version:
--    0x00 0x01
--  Protocol:
--    StreamProtocol
--    SingleOpProtocol
--    MultiplexProtocol
--  StreamProtocol:
--    0x4b
--  SingleOpProtocol:
--    0x4c
--  MultiplexProtocol:
--    0x4d
--  Messages:
--    Message
--    Messages Message

----
-- Connects to a remote service. The connection process creates a
-- socket and does some handshaking. If this is successful,
-- we are definitely talking to an RMI service.
function RmiDataStream:connect(host, port)
  local status, err

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  --  local bsocket = BufferedSocket:new()
  socket:connect(host,port, "tcp")

  -- Output and input
  local dos = JavaDOS:new(BufferedWriter:new(socket))
  local dis = JavaDIS:new(BufferedReader:new(socket))

  -- Start sending a message --
  -- Add Header, Version and Protocol

  --dos:write('JRMI' .. bin.pack('H', Version .. Proto.Stream))
  dos:writeInt(1246907721) -- == JRMI
  dos:writeShort(Version)
  dos:writeByte(Proto.Stream)
  status = dos:flush()
  if not status then
    return doh(err)
  end

  -- For the StreamProtocol and the MultiplexProtocol, the server must respond with a a byte 0x4e
  -- acknowledging support for the protocol, and an EndpointIdentifier that contains the host name
  -- and port number that the server can see is being used by the client.
  -- The client can use this information to determine its host name if it is otherwise unable to do that for security reasons.

  -- Read ack
  status, err = self:readAck(dis)
  if not status then
    return doh("No ack received from server:" .. tostring(err))
  end

  -- The client must then respond with another EndpointIdentifier that contains the clients
  -- default endpoint for accepting connections. This can be used by a server in the MultiplexProtocol case to identify the client.

  dos:writeUTF("127.0.0.1") -- TODO, write our own ip instead (perhaps not necessary, since we are not using MultiplexProtocol
  dos:writeInt(0) -- Port ( 0 works fine)
  dos:flush()
  self.dos = dos
  self.dis =dis
  return true
end

-- Reads a DgcAck message, which is sent during connection handshake
--@param dis - a JavaDIS to read from
--@return status
--@return error message
function RmiDataStream:readAck(dis)
  local status, ack = dis:readByte()

  if not status then return doh( "Could not read data") end

  if ack ~= 78 then
    return doh("No ack received: ".. tostring(ack))
  end
  local status, host = dis:readUTF()
  if not status then return false, "Could not read data" end
  local status, port = dis:readUnsignedInt()
  if not status then return false, "Could not read data" end

  dbg("RMI-Ack received (host %s, port: %d) " , host, port)
  return true
end

-- Sends an RMI method call
--@param out - a JavaDos outputstream
--@param objNum -object id (target of call)
--@param hash - the hashcode for the class that is invoked
--@param op - the operation number (method) invoked
--@param arguments - optional, if arguments are needed to this method. Should be an Arguments table
--  or something else which has a getData() function to get binary data
function RmiDataStream:writeMethodCall(out,objNum, hash, op, arguments)
  dbg("Invoking object %s, hash %s, opNum %s, args %s", tostring(objNum), tostring(hash), tostring(op), tostring(arguments))
  local dos = self.dos
  local dis = self.dis

  -- Send Call:
  dos:writeByte(0x50)
  -- Send Magic 0xaced
  dos:writeShort(0xACED)
  -- Send version 0x0005
  dos:writeShort(0x0005)
  -- Send TC_BLOKDATA
  dos:writeByte(0x77)

  -- send length (byte)
  dos:writeByte(0x22)

  -- From sun.rmi.transport.StreamRemoteCall :
  --   // write out remote call header info...
  --   // call header, part 1 (read by Transport)
  --   conn.getOutputStream().write(TransportConstants.Call);
  --   getOutputStream();           // creates a MarshalOutputStream
  --   id.write(out);               // object id (target of call)
  --   // call header, part 2 (read by Dispatcher)
  --   out.writeInt(op);            // method number (operation index)
  --   out.writeLong(hash);         // stub/skeleton hash
  -- Send rest of the call

  local unique, time, count =0,0,0

  dos:writeLong(objNum);-- id objNum
  dos:writeInt(unique); -- space
  dos:writeLong(time);
  dos:writeShort(count);
  dos:writeInt(op)
  dos:pack('H',hash)

  -- And now, the arguments
  if arguments ~= nil then
    dos:write(arguments:getData())
  end


  dos:flush()

end
---
-- Invokes a method over RMI
--@param methodData, a table which should contain the following
--@param objNum -object id (target of call)
--@param hash - the hashcode for the class that is invoked
--@param op - the operation number (method) invoked
--@param arguments - optional, if arguments are needed to this method. Should be an Arguments table
--  or something else which has a getData() function to get binary data
--@return status
--@return a JavaClass instance
function RmiDataStream:invoke(objNum, hash, op, arguments)
  local status, data
  local out = self.out
  local dis = self.dis
  self:writeMethodCall(out,objNum,hash, op, arguments)
  local status, retByte = dis:readByte()
  if not status then return false, "No return data received from server" end

  if 0x51 ~= retByte then -- 0x51 : Returndata
    return false, "No return data received from server"
  end

  status, data = self:readReturnData(dis)
  return status, data
end

---
-- Reads an RMI ReturnData packet
--@param dis a JavaDIS inputstream
function RmiDataStream:readReturnData(dis)

  --[[
  From -http://turtle.ee.ncku.edu.tw/docs/java/jdk1.2.2/guide/rmi/spec/rmi-protocol.doc3.html :
  A ReturnValue of an RMI call consists of a return code to indicate either a normal or
  exceptional return, a UniqueIdentifier to tag the return value (used to send a DGCAck if necessary)
  followed by the return result: either the Value returned or the Exception thrown.


  CallData: ObjectIdentifier Operation Hash (Arguments)
  ReturnValue:
    0x01 UniqueIdentifier (Value)
    0x02 UniqueIdentifier Exception

  ObjectIdentifier: ObjectNumber UniqueIdentifier
  UniqueIdentifier: Number Time Count
  Arguments: Value Arguments Value
  Value: Object Primitive

  Example:  [ac ed][00 05][77][0f][01][25 14 95 21][00 00 01 2b 16 9a 62 5a 80 0b]
      [magc][ver    ][BL][L ][Ok][ --------------- not interesting atm ----------------------]

  --]]

  -- We need to be able to read at least 7 bytes
  -- If that is doable, we can ignore the status on the following readbyte operations
  if not dis:canRead(7) then
    return doh("Not enough data received")
  end

  local status, magic = dis:readShort() -- read magic
  local status, version = dis:readShort() -- read version


  local status, typ = dis:readByte()
  if typ ~= TC.TC_BLOCKDATA then
    return doh("Expected block data when reading return data")
  end
  local status, len = dis:readByte() -- packet length
  --dis:setReadLimit(len)
  local status, ex = dis:readByte() -- 1=ok, 2=exception thrown
  if ex ~= 1 then
    return doh("Remote call threw exception")
  end

  -- We can skip the rest of this block
  dis:skip(len -1)

  -- Now, the return value object:
  local status, x = readObject0(dis)
  dbg("Read object, got %d left in buffer", dis.bReader:bufferSize())


  if(dis.bReader:bufferSize() > 0) then
    local content = dis.bReader:unpack('H'..tostring(dis.bReader:bufferSize()))
    dbg("Buffer content: %s" ,content)
  end
  return status, x
end
---
-- Deserializes a serialized java object
function readObject0(dis)

  local finished = false
  local data, status, responseType

  status, responseType = dis:readByte()
  if not status then
    return doh("Not enough data received")
  end

  dbg("Reading object of type : %s" , RMIUtils.tcString(responseType))
  local decoder = TypeDecoders[responseType]
  if decoder ~= nil then
    status, data = decoder(dis)
    if not status then return doh("readObject0: Could not read data %s", tostring(data)) end
    dbg("Read: %s", tostring(data))
    return true, data
  else
    return doh("No decoder found for responsetype: %s" , RMIUtils.tcString(responseType))
  end
end
function readString(dis)
  return dis:readUTF()
end
-- Reads return type array
function readArray(dis)
  local array  = JavaArray:new()
  dbg("Reading array class description")
  local status, classDesc = readClassDesc(dis)
  array:setClass(classDesc)
  dbg("Reading array length")
  local status, len = dis:readInt()

  if not status then
    return doh("Could not read data")
  end

  array:setLength(len)
  dbg("Reading array of length is %X", len)
  for i =1, len, 1 do
    local status, object = readObject0(dis)
    array:setValue(i,object)
  end
  return true, array
end

function readClassDesc(dis)
  local status, p = dis:readByte()
  if not status then return doh( "Could not read data" ) end

  dbg("reading classdesc: %s" , RMIUtils.tcString(p))

  local val

  if p == TC.TC_CLASSDESC then
    dbg("Reading TC_CLASSDESC")
    status, val = readNonProxyDesc(dis)
  elseif p == TC.TC_NULL then
    dbg("Reading TC_NULL")
    status, val = true, nil
  elseif p == TC.TC_PROXYCLASSDESC then
    dbg("Reading TC_PROXYCLASSDESC")
    status, val = readProxyDesc(dis)
  else
    return doh("TC_classdesc is other %d", p)
  end

  if not status then
    return doh("Error reading class description")
  end
  return status, val


end
function readOrdinaryObject(dis)
  local status, desc =  readClassDesc(dis)
  if not status then
    return doh("Error reading ordinary object")
  end


  if  desc:isExternalizable() then
    dbg("External content")
    local status, extdata = readExternalData(dis)
    if status then
      desc["externalData"] = extdata
    end
  else
    dbg("Serial content")
    local status, serdata = readExternalData(dis)
    if status then
      desc["externalData"] = serdata
      local status, data =parseExternalData(desc)
      if status then
        desc['externalData'] = data
      end
    end
  end
  return status, desc

end

-- Attempts to read some object-data, at least remove the block
-- header. This method returns the external data in 'raw' form,
-- since it is up to each class to define an readExternal method
function readExternalData(dis)
  local  data = {}
  while dis.bReader:bufferSize() > 0 do
    local status, tc= dis:readByte()
    if not status then
      return doh("Could not read external data")
    end
    dbg("readExternalData: %s", RMIUtils.tcString(tc))
    local status, len, content
    if tc == TC.TC_BLOCKDATA then
      status, len = dis:readByte()
      status, content = dis.bReader:skip(len)
      --print(bin.unpack("H"..tostring(#content),content))
      --print(makeStringReadable(content))
      dbg("Read external data (%d bytes): %s " ,len, content)
      --local object = ExternalClassParsers['java.rmi.server.RemoteObject'](dis)
      --print(object)
      return status, content
    elseif tc == TC.TC_BLOCKDATALONG then
      status, len = dis:readUnsignedInt()
      status, content = dis.bReader:skip(len)
      return status, content
    elseif tc == TC.TC_ENDBLOCKDATA then
      --noop
    else
      return doh("Got unexpected field in readExternalData: %s ", RMIUtils.tcString(tc))
    end
  end
end

----
-- ExternalClassParsers : External Java Classes
-- This 'class' contains information about certain specific java classes,
-- such as UnicastRef, UnicastRef2. After such an object has been read by
-- the object serialization protocol, it will contain a lump of data which is
-- in 'external' form, and needs to be read in a way which is specific for the class
-- itself. This class contains the implementations for reading out the
-- 'goodies' of e.g UnicastRef, which contain important information about
-- where another RMI-socket is listening and waiting for someone to connect.
ExternalClassParsers = {
  ---
  --@see sun.rmi.transport.tcp.TCPEndpoint
  --@see sun.rmi.server.UnicastRef
  --@see sun.rmi.server.UnicastRef2
  UnicastRef = function(dis)
    local stat, host = dis:readUTF();
    if not stat then return doh("Parsing external data, could not read host (UTF)") end
    local status, port = dis:readUnsignedInt();
    if not stat then return doh("Parsing external data, could not read port (int)") end

    dbg("a host: %s, port %d", host, port)
    return true, ("@%s:%d"):format(host,port)
  end,
  ---
  --@see sun.rmi.transport.tcp.TCPEndpoint
  --@see sun.rmi.server.UnicastRef
  --@see sun.rmi.server.UnicastRef2
  UnicastRef2 = function(dis)
    local stat, form = dis:readByte();
    if not stat then return doh("Parsing external data, could not read byte") end
    if form == 0  or form == 1 then-- FORMAT_HOST_PORT or  FORMAT_HOST_PORT_FACTORY
      local stat, host = dis:readUTF();
      if not stat then return doh("Parsing external data, could not read host (UTF)") end
      local status, port = dis:readUnsignedInt();
      if not stat then return doh("Parsing external data, could not read port (int)") end
      dbg("b host: %s, port %d", host, port)
      if form ==0 then
        return true, ("@%s:%d"):format(host,port)
      end
      -- for FORMAT_HOST_PORT_FACTORY, there's an object left to read
      local status, object = readObject0(dis)
      return true, ("@%s:%d"):format(host,port)
      --return true, {host = host, port = port, factory = object}
    else
      return doh("Invalid endpoint format")
    end
  end
}
--@see java.rmi.server.RemoteObject:readObject()
ExternalClassParsers['java.rmi.server.RemoteObject'] = function(dis)
  local status, refClassName = dis:readUTF()
  if not status then return doh("Parsing external data, could not read classname (UTF)") end
  if #refClassName == 0 then
    local status, ref = readObject0(dis)
    return status, ref
  end
  dbg("Ref class name: %s ", refClassName)
  local parser = ExternalClassParsers[refClassName]

  if parser == nil then
    return doh("No external class reader for %s" , refClassName)
  end

  local status, object = parser(dis)
  return status, object
end

-- Attempts to parse the externalized data of an object.
--@return status, the object data
function parseExternalData(j_object)

  if j_object == nil then
    return doh("parseExternalData got nil object")
  end

  local className = j_object:getName()

  -- Find parser for the object, move up the hierarchy
  local obj = j_object
  local parser = nil
  while(className  ~= nil) do
    parser = ExternalClassParsers[className]
    if parser ~= nil then break end

    obj = obj:getSuperClass()
    if obj== nil then break  end-- No more super classes
    className = obj:getName()
  end

  if parser == nil then
    return doh("External reader for class %s is not implemented", tostring(className))
  end
  -- Read the actual object, start by creating a new dis based on the data-string
  local dis = JavaDIS:new(BufferedReader:new(nil,j_object.externalData))
  local status, object = parser(dis)
  if not status then
    return doh("Could not parse external data")
  end
  return true, object
end

-- Helper function to display data
-- returns the string with all non-printable chars
-- coded as hex
function makeStringReadable(data)
  return data:gsub("[\x00-\x1f\x7f-\xff]", function (x)
      return ("\\x%02x"):format(x:byte())
    end)
end

function readNonProxyDesc(dis)
  dbg("-- entering readNonProxyDesc--")
  local j_class = JavaClass:new()
  local status, classname = dis:readUTF()
  if not status then return doh( "Could not read data" ) end
  j_class:setName(classname)

  local status, serialID = dis:readLongAsHexString()
  if not status then return doh("Could not read data") end
  j_class:setSerialID(serialID)

  dbg("Set serial ID to %s", tostring(serialID))

  local status, flags = dis:readByte()
  if not status then return doh("Could not read data") end
  j_class:setFlags(flags)


  local status, fieldCount = dis:readShort()
  if not status then return doh( "Could not read data") end

  dbg("Fieldcount %d", fieldCount)

  local fields = {}
  for i =0, fieldCount-1,1 do
    local status, fieldDesc = readFieldDesc(dis)
    j_class:addField(fieldDesc)
    -- Need to store in list, the field values need to be read
    -- after we have finished reading the class description
    -- hierarchy
    table.insert(fields,fieldDesc)
  end
  local status, customStrings = skipCustomData(dis)
  if status and customStrings ~= nil and #customStrings > 0 then
    j_class:setCustomData(customStrings)
  end

  local _,superDescriptor = readClassDesc(dis)

  j_class:setSuperClass(superDescriptor)
  dbg("Superclass read, now reading %i field values", #fields)
  --Read field values
  for i=1, #fields, 1 do
    local status, fieldType = dis:readByte()
    local value = nil
    if ( TypeDecoders[fieldType] ) then
      status, value= TypeDecoders[fieldType](dis)
    else
      dbg("error reading".. RMIUtils.tcString(fieldType))
      return
    end
    dbg("Read fieldvalue ".. tostring(value) .. " for field ".. tostring(fields[i]))
    fields[i]:setValue(value)
  end
  dbg("-- leaving readNonProxyDesc--")
  return true, j_class


end

function readProxyDesc(dis)
  dbg("-- in readProxyDesc--")
  local interfaces = ''
  local superclass = nil
  local status, ifaceNum= dis:readInt()
  if not status then return doh("Could not read data") end
  --dbg("# interfaces: %d" , ifaceNum)
  while ifaceNum > 0 do
    local status, iface = dis:readUTF()
    if not status then return doh( "Could not read data") end
    --table.insert(interfaces, iface)
    interfaces = interfaces .. iface ..', '
    dbg("Interface: %s " ,iface)
    ifaceNum = ifaceNum-1
  end

  local j_class = JavaClass:new()

  local status, customStrings = skipCustomData(dis)
  if status and customStrings ~= nil and #customStrings > 0 then
    j_class:setCustomData(customStrings)
  end

  local _,superDescriptor = readClassDesc(dis)


  --print ("superdescriptor", superDescriptor)
  j_class:setSuperClass(superDescriptor)
  j_class:setInterfaces(interfaces)

  dbg("-- leaving readProxyDesc--")
  return true, j_class

end
--
-- Skips over all block data and objects until TC_ENDBLOCKDATA is
-- encountered.
-- @see java.io.ObjectInputStream.skipCustomData()
--@return status
--@return any strings found while searching
function skipCustomData(dis)
  -- If we come across something interesting, just put it into
  -- the returnData list
  local returnData = {}
  while true do
    local status, p = dis:readByte()
    if not status then
      return doh("Could not read data")
    end

    if not status then return doh("Could not read data") end
    dbg("skipCustomData read %s", RMIUtils.tcString(p))

    if p == TC.TC_BLOCKDATA or p == TC.TC_BLOCKDATALONG then
      dbg("continuing")
      --return
    elseif p == TC.TC_ENDBLOCKDATA then
      return true, returnData
    else
      -- In the java impl, this is a function called readObject0. We just
      -- use the read null, otherwise error
      if p == TC.TC_NULL then
        -- No op, already read the byte, continue reading
      elseif p == TC.TC_STRING then
        --dbg("A string is coming!")
        local status,  str = dis:readUTF()
        if not status then
          return doh("Could not read data")
        end
        dbg("Got a string, but don't know what to do with it! : %s",str)
        -- Object serialization is a bit messy. I have seen the
        -- classpath being sent over a customdata-field, so it is
        -- definitely interesting. Quick fix to get it showing
        -- is to just stick it onto the object we are currently at.
        -- So, just put the string into the returnData and continue
        table.insert(returnData, str)
      else
        return doh("Not implemented in skipcustomData:: %s", RMIUtils.tcString(p))
      end
    end
  end
end

function readFieldDesc(dis)
  -- fieldDesc:
  --   primitiveDesc
  --   objectDesc
  -- primitiveDesc:
  --   prim_typecode fieldName
  -- objectDesc:
  --   obj_typecode fieldName className1
  --   prim_typecode:
  --   `B'  // byte
  --   `C'  // char
  --   `D'  // double
  --   `F'  // float
  --   `I'  // integer
  --   `J'  // long
  --   `S'  // short
  --   `Z'  // boolean
  -- obj_typecode:
  --   `[`  // array
  --   `L'  // object
  local j_field = JavaField:new()

  local status, c = dis:readByte()
  if not status then return doh("Could not read data") end

  local char = string.char(c)

  local status, name = dis:readUTF()
  if not status then return doh("Could not read data") end

  local fieldType = ('primitive type: (%s) '):format(char)
  dbg("Fieldtype, char = %s, %s", tostring(fieldType), tostring(char))
  if char == 'L' or char == '['  then
    -- These also have classname which tells the type
    -- on the field
    local status, fieldclassname = readTypeString(dis)
    if not status then return doh("Could not read data") end
    if char == '[s' then
      fieldType = fieldclassname .. " []"
    else
      fieldType = fieldclassname
    end
  end

  if not status then
    return false, fieldType
  end

  dbg("Field description: name: %s, type: %s", tostring(name), tostring(fieldType))

  j_field:setType(fieldType)
  j_field:setName(name)
  -- setType = function( self, typ ) self.type = typ end,
  -- setSignature = function( self, sig ) self.signature = sig end,
  -- setName = function( self, name ) self.name = name end,
  -- setObjectType = function( self, ot ) self.object_type = ot end,
  -- setReference = function( self, ref ) self.ref = ref end,

  dbg("Created java field:".. tostring(j_field))

  return true, j_field

end

function readTypeString(dis)
  local status, tc = dis:readByte()
  if not status then return doh("Could not read data") end
  if  tc == TC.TC_NULL then
    return true, nil
  elseif tc== TC.TC_REFERENCE then
    return doh("Not implemented, readTypeString(TC_REFERENCE)");
  elseif tc == TC.TC_STRING then
    return dis:readUTF()
  elseif tc == TC.TC_LONGSTRING then
    --TODO, add this (will throw error as is)
    return dis:readLongUTF()
  end
end

TypeDecoders =
{
  [TC.TC_ARRAY] = readArray,
  [TC.TC_CLASSDESC] = readClassDesc,
  [TC.TC_STRING] = readString,
  [TC.TC_OBJECT] = readOrdinaryObject,
}

---
-- Registry
-- Class to represent the RMI Registry.
--@usage:
-- registry = rmi.Registry:new()
-- status, data = registry:list()
Registry ={
  new = function  (self,host, port)
    local o ={}   -- create object
    setmetatable(o, self)
    self.__index = self -- DIY inheritance
    -- Hash code for sun.rmi.registry.RegistryImpl_Stub, which we are invoking :
    -- hex: 0x44154dc9d4e63bdf, dec: 4905912898345647071
    self.hash = '44154dc9d4e63bdf'
    -- RmiRegistry object id is 0
    self.objId = 0
    o.host = host
    o.port = port
    return o
  end
}
-- Connect to the remote registry.
--@return status
--@return error message
function Registry:_handshake()
  local out = RmiDataStream:new()
  local status, err = out:connect(self.host,self.port)

  if not status then
    return doh("Registry connection failed: %s", tostring(err))
  end
  dbg("Registry connection OK "..tostring(out.bsocket) )
  self.out = out
  return true
end
---
-- List the named objects in the remote RMI registry
--@return status
--@return a table of strings , or error message
function Registry:list()
  if not self:_handshake() then
    return doh("Handshake failed")
  end
  -- Method list() is op number 1
  return self.out:invoke(self.objId, self.hash,1)
end
---
-- Perform a lookup on an object in the Registry,
-- takes the name which is bound in the registry
-- as argument
--@return status
--@return JavaClass-object
function Registry:lookup(name)
  self:_handshake()
  -- Method lookup() is op number 2
  -- Takes a string as arguments
  local a = Arguments:new()
  a:addString(name)
  return self.out:invoke(self.objId, self.hash,2, a)
end
----
-- Arguments class
-- This class is meant to handle arguments which is sent to a method invoked
-- remotely. It is mean to contain functionality to add java primitive datatypes,
-- such as pushInt, pushString, pushLong etc. All of these are not implemented
-- currently
--@usage: When invoking a remote method
-- use this class in this manner:
--  Arguments a = Arguments:new()
--  a:addString("foo")
--  datastream:invoke{objNum=oid, hash=hash, opNum = opid, arguments=a}
--  ...
--
Arguments = {

  new = function  (self,o)
    o = o or {}   -- create object if user does not provide one
    setmetatable(o, self)
    self.__index = self -- DIY inheritance
    -- We use a buffered socket just to be able to use a javaDOS for writing
    self.dos = JavaDOS:new(BufferedWriter:new())
    return o
  end,
  addString = function(self, str)
    self.dos:writeByte(TC.TC_STRING)
    self.dos:writeUTF(str)
  end,
  addRaw = function(self, str)
    self.dos:write(str)
  end,
  getData = function(self)
    local _, res = self.dos:flush()
    return res
  end
}


---
-- RMIUtils class provides some some codes and definitions from Java
-- There are three types of output messages: Call, Ping  and DgcAck.
-- A Call encodes a method invocation. A Ping  is a transport-level message
-- for testing liveness of a remote virtual machine.
-- A DGCAck is an acknowledgment directed to a
-- server's distributed garbage collector that indicates that remote objects
-- in a return value from a server have been received by the client.

RMIUtils = {

  -- Indicates a Serializable class defines its own writeObject method.
  SC_WRITE_METHOD = 0x01,
  -- Indicates Externalizable data written in Block Data mode.
  SC_BLOCK_DATA = 0x08,
  -- Bit mask for ObjectStreamClass flag. Indicates class is Serializable.
  SC_SERIALIZABLE = 0x02,
  --Bit mask for ObjectStreamClass flag. Indicates class is Externalizable.
  SC_EXTERNALIZABLE = 0x04,
  --Bit mask for ObjectStreamClass flag. Indicates class is an enum type.
  SC_ENUM = 0x10,

  flagsToString = function(flags)
    local retval = ''
    if ( bit.band(flags, RMIUtils.SC_WRITE_METHOD) ~= 0) then
      retval = retval .. " WRITE_METHOD"
    end
    if ( bit.band(flags, RMIUtils.SC_BLOCK_DATA) ~= 0) then
      retval = retval .. " BLOCK_DATA"
    end
    if ( bit.band(flags, RMIUtils.SC_EXTERNALIZABLE) ~= 0) then
      retval = retval .. " EXTERNALIZABLE"
    end
    if ( bit.band(flags, RMIUtils.SC_SERIALIZABLE) ~= 0) then
      retval = retval .. " SC_SERIALIZABLE"
    end
    if ( bit.band(flags, RMIUtils.SC_ENUM) ~= 0) then
      retval = retval .. " SC_ENUM"
    end
    return retval
  end,
  tcString = function (constant)
    local x = TC.Strings[constant] or "Unknown code"
    return ("%s (0x%x)"):format(x,tostring(constant))

  end,

}

local RMIMessage = {
  Call = 0x50,
  Ping = 0x52,
  DgcAck= 0x54,
}
STREAM_MAGIC =  0xaced
STREAM_VERSION = 5

baseWireHandle = 0x7E0000

return _ENV;
