---
-- GIOP Library supporting a very limited subset of operations
--
-- Summary
-- -------
--  The library currently provides functionality to connect and query the
--  CORBA naming service for a list of available objects.
--
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
--   o Comm
--    - Implements a number of functions to handle communication over the
--        the socket.
--
--   o Helper
--    - A helper class that provides easy access to the rest of the library
--
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
--  helper   = giop.Helper:new(host, port)
--  status, err = helper:Connect()
--  status, ctx = helper:GetNamingContext()
--  status, objs = helper:ListObjects(ctx)
-- </code>
--
-- Additional information
-- ----------------------
-- The implementation is based on packet dumps and the decoding Wireshark
-- provides.
--
-- This implementation is tested and known to work against:
-- x Sun's JAVA orbd
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>
--

--
-- Version 0.1
-- Created 08/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

local bin = require "bin"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("giop", stdnse.seeall)

-- A bunch of constants
Constants = {

  SyncScope = {
    WITH_TARGET = 3,
  },

  ServiceContext = {
    CODESETS = 1,
    SENDING_CONTEXT_RUNTIME = 6,
    NEO_FIRST_SERVICE_CONTEXT = 1313165056,
  },

  ReplyStatus = {
    SYSTEM_EXCEPTION = 2,
  },

  VERSION_1_0 = 1,
  VERSION_1_2 = 0x0201,

  NAMESERVICE = "NameService\0",
}


Packet = {}

Packet.GIOP = {

  magic   = "GIOP",
  version = 0x0001,
  byte_order = 0,

  --- Creates a Packet.GIOP
  --
  -- @param msgtype number containing the message type
  -- @param data string containing the message data
  -- @return obj a new Packet.GIOP instance
  new = function( self, msgtype, data )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.type = msgtype
    o.data = data
    o.size = data and #data or 0
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the instance data
  __tostring = function( self )
    return bin.pack("<ASCC>IA", self.magic, self.version, self.byte_order, self.type, self.size, self.data )
  end,

  --- Sets the packet version
  --
  -- @param version number containing the version to use
  setVersion = function( self, version ) self.version = version end,

  --- Receives the packet over the socket
  --
  -- @param socket containing the already connected socket
  -- @return status true on success, false on failure
  -- @return err containing the error message if status is false
  recv = function( self, socket )
    local status, data = socket:receive_buf(match.numbytes(12), true)
    local pos

    if ( not(status) ) then return false, "Failed to read Packet.GIOP" end

    pos, self.magic, self.version, self.byte_order,
    self.type = bin.unpack("<A4SCC", data )

    pos, self.size = bin.unpack( ( self.byte_order == 0 and ">" or "<") .. "I", data, pos )

    status, data = socket:receive_buf(match.numbytes(self.size), true)
    if ( not(status) ) then return false, "Failed to read Packet.GIOP" end

    self.data = data
    return true
  end,
}

ServiceContext = {

  --- Creates a ServiceContext
  --
  -- @param id number containing the context id
  -- @param data the service context data
  -- @param pad [optional] number used to pad after the service context
  -- @return obj a new ServiceContext instance
  new = function( self, id, data, pad )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.id = id
    o.data = data or ""
    o.pad = pad
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the instance data
  __tostring = function( self )
    if ( self.pad ) then
      return bin.pack(">IIAS", self.id, #self.data, self.data, self.pad)
    else
      return bin.pack(">IIA", self.id, #self.data, self.data)
    end
  end,
}

--- Creates a SendingContextRuntime
SendingContextRuntime =
{
  --- Creates a SendingContextRuntime
  --
  -- @param lhost string containing the source ip address
  -- @return obj a new SendingContextRuntime instance
  new = function(self, lhost )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.data = bin.pack(">HIAH",
      [[
      000000000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746
      578742f436f6465426173653a312e300000000001000000000000006e000102
      00
      ]], #lhost + 1, lhost .. "\0",
      [[
      00ec5100000019afabcb000000000249765d6900000008000000000000000014
      0000000000000200000001000000200000000000010001000000020501000100
      01002000010109000000010001010000000026000000020002
      ]] )
    return o
  end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the instance data
  __tostring = function( self ) return self.data end,
}

Packet.GIOP.reply = {

  --- Creates a new Packet.GIOP.reply instance
  --
  -- @return obj a new Packet.GIOP.get instance
  new = function( self )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    self.sc = {}
    self.GIOP = Packet.GIOP:new()
    return o
  end,

  --- Receives a Packet.GIOP.reply from the socket
  --
  -- @param socket already connected to the server
  -- @return status true on success, false on failure
  -- @return err error message if status is false
  recv = function( self, socket )
    local status, err = self.GIOP:recv( socket )
    local pos, tmp
    local bo = ( self.GIOP.byte_order == 0 and ">" or "<")

    if( not(status) ) then return false, err end

    if ( self.GIOP.version == Constants.VERSION_1_2 ) then
      pos, self.request_id, self.reply_status = bin.unpack(bo .. "II", self.GIOP.data, pos )
      pos, tmp = bin.unpack( bo .. "I", self.GIOP.data, pos )
    elseif ( self.GIOP.version == Constants.VERSION_1_0 ) then
      pos, tmp = bin.unpack( bo .. "I", self.GIOP.data )
    end

    for i=1, tmp do
      local ctx_id, ctx_len, ctx_data
      pos, ctx_id, ctx_len = bin.unpack( bo .. "II", self.GIOP.data, pos )
      pos, ctx_data = bin.unpack("A" .. ctx_len, self.GIOP.data, pos )
      if ( i ~= tmp ) then pos = pos + 2 end
      table.insert( self.sc, ServiceContext:new( ctx_id, ctx_data ) )
    end

    if ( self.GIOP.version == Constants.VERSION_1_0 ) then
      pos, self.request_id, self.reply_status, self.stub_data = bin.unpack( bo .. "IIA" .. ( #self.GIOP.data - pos - 8 ), self.GIOP.data, pos )
    elseif ( pos < #self.GIOP.data ) then
      pos, self.data = bin.unpack("A" .. (#self.GIOP.data - pos), self.GIOP.data, pos )
    end

    return true
  end,

}

Packet.GIOP.get = {

  resp_expected = 1,
  key_length = 4,
  princ_len = 0,

  --- Creates a new Packet.GIOP._is_a instance
  --
  -- @param id the packet identifier
  -- @param key number containing the object key
  -- @param data string containing the stub data
  -- @return obj a new Packet.GIOP.get instance
  new = function( self, id, key, data )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.op = "get\0"
    o.id = id
    o.key = key
    o.data = data
    o.sc = {}
    return o
  end,

  --- Creates and adds a service context to the packet
  --
  -- @param id number containing the context id
  -- @param data the service context data
  -- @param pad [optional] number used to pad after the service context
  addServiceContext = function( self, id, data, pad ) table.insert( self.sc, ServiceContext:new(id, data, pad) ) end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function( self )
    local data = bin.pack(">I", #self.sc)
    local pad = 0

    for i=1, #self.sc do
      data = data .. tostring( self.sc[i])
    end

    data = data .. bin.pack( ">ICCCCIIIAIA", self.id, self.resp_expected, pad, pad, pad,
    self.key_length, self.key, #self.op, self.op, self.princ_len, self.data )

    return tostring( Packet.GIOP:new( 0, data ) )
  end,

}

Packet.GIOP._is_a =
{

  --- Creates a new Packet.GIOP._is_a instance
  --
  -- @param id the packet identifier
  -- @param flags [optional]
  -- @param keyaddr string containing the keyaddr data
  -- @return obj a new Packet.GIOP._is_a instance
  new = function( self, id, flags, key_addr )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.op = "_is_a\0"
    o.id = id
    o.target_addr = 0 -- KeyAddr
    o.key_addr = key_addr
    o.flags = flags or Constants.SyncScope.WITH_TARGET -- SyncScope WITH_TARGET
    o.sc = {}
    return o
  end,

  --- Creates and adds a service context to the packet
  --
  -- @param id number containing the context id
  -- @param data the service context data
  -- @param pad [optional] number used to pad after the service context
  addServiceContext = function( self, id, data, pad ) table.insert( self.sc, ServiceContext:new(id, data, pad) ) end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function( self )
    local TYPE_ID = "IDL:omg.org/CosNaming/NamingContextExt:1.0\0"
    local RESERVED = 0
    local UNKNOWN, UNKNOWN2, UNKNOWN3 = 2, 1, 0
    local data = bin.pack(">ICCCCSSIAIASI", self.id, self.flags, RESERVED, RESERVED, RESERVED, self.target_addr,
    UNKNOWN, #self.key_addr, self.key_addr, #self.op, self.op, UNKNOWN2, #self.sc )

    for i=1, #self.sc do
      data = data .. tostring( self.sc[i])
    end

    data = data .. bin.pack(">IA", #TYPE_ID, TYPE_ID)

    local packet = Packet.GIOP:new( 0, data )
    packet:setVersion( Constants.VERSION_1_2 )

    return tostring( packet )
  end,

}

Packet.GIOP.list =
{
  --- Creates a new Packet.GIOP.list instance
  --
  -- @param id the packet identifier
  -- @param flags [optional]
  -- @param keyaddr string containing the keyaddr data
  -- @param how_many string containing the value to retrieve
  -- @return obj a new Packet.GIOP.list instance
  new = function( self, id, flags, keyaddr, how_many )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.op = "list\0"
    o.id = id
    o.flags = flags or Constants.SyncScope.WITH_TARGET
    o.target_addr = 0 -- KeyAddr
    o.key_addr = keyaddr
    o.how_many = how_many or 1000
    o.sc = {}
    return o
  end,

  --- Creates and adds a service context to the packet
  --
  -- @param id number containing the context id
  -- @param data the service context data
  -- @param pad [optional] number used to pad after the service context
  addServiceContext = function( self, id, data, pad ) table.insert( self.sc, ServiceContext:new(id, data, pad) ) end,

  --- Converts the class to a string suitable to send over the socket
  --
  -- @return string containing the packet data
  __tostring = function( self )
    local RESERVED = 0
    local UNKNOWN, UNKNOWN2, UNKNOWN3 = 2, 1, 6

    local data = bin.pack(">ICCCCSSIAIACCCI", self.id, self.flags, RESERVED, RESERVED,
      RESERVED, self.target_addr, UNKNOWN, #self.key_addr, self.key_addr,
      #self.op, self.op, RESERVED, RESERVED, UNKNOWN2, #self.sc )

    for i=1, #self.sc do
      data = data .. tostring( self.sc[i])
    end

    data = data .. bin.pack(">II", UNKNOWN3, self.how_many )
    local packet = Packet.GIOP:new( 0, data )
    packet:setVersion( Constants.VERSION_1_2 )

    return tostring( packet )
  end,

}

-- Static class containing various message decoders
MessageDecoder = {

  --- Decodes a get response
  --
  -- @param packet the GIOP packet as received by the comm
  --       <code>exchGIOPPacket</code> function
  -- @return status true on success, false on failure
  -- @return table containing <code>ip</code> and <code>ctx</code>
  ["get"] = function( packet )
    local bo = ( packet.GIOP.byte_order == 0 and ">" or "<")
    local pos, len = bin.unpack(bo .. "I", packet.stub_data)
    local ip, ctx

    pos = pos + len + 16

    pos, len = bin.unpack(bo .. "I", packet.stub_data, pos)
    pos, ip = bin.unpack( bo .. "A" .. len, packet.stub_data, pos)

    pos = pos + 3
    pos, len = bin.unpack(bo .. "I", packet.stub_data, pos)
    pos, ctx = bin.unpack( bo .. "A" .. len, packet.stub_data, pos)

    return true, { ip = ip, ctx = ctx}
  end,

  --- Decodes a _is_a response (not implemented)
  --
  -- @param packet the GIOP packet as received by the comm
  --       <code>exchGIOPPacket</code> function
  -- @return status, always true
  ["_is_a"] = function( packet )
    return true
  end,

  --- Decodes a list response
  --
  -- @param packet the GIOP packet as received by the comm
  --       <code>exchGIOPPacket</code> function
  -- @return status true on success, false on failure
  -- @return table containing <code>id</code>, <code>kind</code> and
  --         <code>enum</code> or error message if status is false
  ["list"] = function( packet )
    local bo = ( packet.GIOP.byte_order == 0 and ">" or "<")
    local pos, seq_len = bin.unpack( bo .. "I", packet.data, 7)
    local objs = {}

    for i=1, seq_len do
      local seq_len_of_bind_name
      local len, name
      local obj = {}

      pos, seq_len_of_bind_name = bin.unpack( bo .. "I", packet.data, pos)
      if ( seq_len_of_bind_name ~= 1 ) then return false, "Sequence length of Binding_binding_name was greater than 1" end

      pos, len = bin.unpack( bo .. "I", packet.data, pos )
      pos, obj.id = bin.unpack( "A" .. len - 1, packet.data, pos )

      -- Account for terminating zero
      pos = pos + 1

      -- Account for undecoded data
      pos = pos + ( ( len % 4 > 0 ) and ( 4 - ( len % 4 ) ) or 0 )
      pos = pos + 3

      pos, obj.kind = bin.unpack("C", packet.data, pos)

      -- Account for undecoded data
      pos = pos + 4
      pos, obj.enum = bin.unpack( bo .. "I", packet.data, pos )
      table.insert( objs, obj )
    end

    return true, objs
  end,

}

Comm = {

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

  --- Sends and receives a GIOP packet
  --
  -- @param packet containing a Packet.* object, the object must
  --        implement the __tostring meta method
  -- @return status true on success, false on failure
  -- @return data decoder specific data, see the corresponding
  --         MessageDecoder for more information.
  exchGIOPPacket = function( self, packet )
    local status, err = self.socket:send( tostring(packet) )
    local op = packet.op:sub(1, -2)
    local data

    if( not(status) ) then return false, err end
    packet = Packet.GIOP.reply:new()

    status, err = packet:recv( self.socket )
    if( not(status) ) then return false, err end

    if ( MessageDecoder[op] ) then
      status, data = MessageDecoder[op]( packet )
    else
      return false, ("No message decoder for op (%s)"):format(op)
    end

    return status, data
  end,

}


Helper = {

  new = function(self, host, port )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.socket = nmap.new_socket()
    return o
  end,

  GetNamingContext = function( self )
    local packet = Packet.GIOP.get:new( 5, 0x494e4954, bin.pack(">IA", #Constants.NAMESERVICE, Constants.NAMESERVICE) )
    local status, ctx, lhost, pos, len, bo, tmp

    packet:addServiceContext( 17, "\0\x02", 0)
    packet:addServiceContext( Constants.ServiceContext.NEO_FIRST_SERVICE_CONTEXT, "\0\x14", 0)
    packet:addServiceContext( Constants.ServiceContext.SENDING_CONTEXT_RUNTIME, tostring(SendingContextRuntime:new( self.lhost )), 0 )

    status, packet = self.comm:exchGIOPPacket( packet )
    if( not(status) ) then return status, packet end

    return true, packet.ctx
  end,

  ListObjects = function( self, keyaddr )
    -- SyncScope WITH_TARGET
    local packet = Packet.GIOP._is_a:new( 5, Constants.SyncScope.WITH_TARGET, keyaddr )
    local status, err, lhost

    status, err = self:Reconnect()
    if( not(status) ) then return false, err end

    packet:addServiceContext( 17, "\0\2", 0x000d)
    packet:addServiceContext( Constants.ServiceContext.CODESETS, "\0\0\0\0\0\1\0\1\0\1\1\9" )
    packet:addServiceContext( Constants.ServiceContext.NEO_FIRST_SERVICE_CONTEXT, "\0\x14", 0x5d69)
    packet:addServiceContext( Constants.ServiceContext.SENDING_CONTEXT_RUNTIME, tostring(SendingContextRuntime:new( self.lhost )), 0 )

    status, packet = self.comm:exchGIOPPacket( packet )
    if( not(status) ) then return status, packet end

    packet = Packet.GIOP.list:new( Constants.ServiceContext.SENDING_CONTEXT_RUNTIME, Constants.SyncScope.WITH_TARGET, keyaddr, 1000 )
    packet:addServiceContext( 17, "\0\2", 0x000d)
    packet:addServiceContext( Constants.ServiceContext.CODESETS, "\0\0\0\0\0\1\0\1\0\1\1\9" )
    packet:addServiceContext( Constants.ServiceContext.NEO_FIRST_SERVICE_CONTEXT, "\0\x14", 0x9c9b)

    status, packet = self.comm:exchGIOPPacket( packet )
    if( not(status) ) then return status, packet end

    return true, packet
  end,

  --- Connects and performs protocol negotiation with the Oracle server
  --
  -- @return true on success, false on failure
  -- @return err containing error message when status is false
  Connect = function( self )
    self.socket:set_timeout(10000)
    local status, data = self.socket:connect( self.host.ip, self.port.number, "tcp" )
    if( not(status) ) then return status, data end
    self.comm = Comm:new( self.socket )

    status, self.lhost = self.socket:get_info()
    if ( not(status) ) then
      self.socket:close()
      return false, "Error failed to get socket information"
    end

    return true
  end,

  Close = function( self )
    return self.socket:close()
  end,

  Reconnect = function( self )
    local status = self:Close()
    if( not(status) ) then return false, "Failed to close socket" end

    status = self:Connect()
    if( not(status) ) then return false, "Failed to re-connect socket" end

    return true
  end,
}

return _ENV;
