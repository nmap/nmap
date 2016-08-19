---
-- This library implements a minimal subset of the BitCoin protocol
-- It currently supports the version handshake and processing Addr responses.
--
-- The library contains the following classes:
--
-- * NetworkAddress - Contains functionality for encoding and decoding the
--                    BitCoin network address structure.
--
-- * Request - Classs containing BitCoin client requests
--     o Version - The client version exchange packet
--
-- * Response - Class containing BitCoin server responses
--     o Version - The server version exchange packet
--     o VerAck  - The server version ACK packet
--     o Addr    - The server address packet
--     o Inv     - The server inventory packet
--
-- * Helper - The primary interface to scripts
--
--@author Patrik Karlsson <patrik@cqure.net>
--@author Andrew Orr <andrew@andreworr.ca>
--@copyright Same as Nmap--See https://nmap.org/book/man-legal.html

--
-- Version 0.2
--
-- Created 11/09/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 17/02/2012 - v0.2 - fixed count parsing
--                           - changed version/verack handling to support
--                             February 20th 2012 bitcoin protocol switchover

local bin = require "bin"
local ipOps = require "ipOps"
local match = require "match"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local table = require "table"
local openssl = stdnse.silent_require('openssl')
_ENV = stdnse.module("bitcoin", stdnse.seeall)

-- A class that supports the BitCoin network address structure
NetworkAddress = {

  NODE_NETWORK = 1,

  -- Creates a new instance of the NetworkAddress class
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @return o instance of NetworkAddress
  new = function(self, host, port)
    local o = {
      host = "table" == type(host) and host.ip or host,
      port = "table" == type(port) and port.number or port,
      service = NetworkAddress.NODE_NETWORK,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Creates a new instance of NetworkAddress based on the data string
  -- @param data string of bytes
  -- @return na instance of NetworkAddress
  fromString = function(data)
    assert(26 == #data, "Expected 26 bytes of data")

    local na = NetworkAddress:new()
    local _
    _, na.service, na.ipv6_prefix, na.host, na.port = bin.unpack("<LH12I>S", data)
    na.host = ipOps.fromdword(na.host)
    return na
  end,

  -- Converts the NetworkAddress instance to string
  -- @return data string containing the NetworkAddress instance
  __tostring = function(self)
    local ipv6_prefix = "00 00 00 00 00 00 00 00 00 00 FF FF"
    local ip = ipOps.todword(self.host)
    return bin.pack("<LH>IS", self.service, ipv6_prefix, ip, self.port )
  end
}

-- The request class container
Request = {

  -- The version request
  Version = {

    -- Creates a new instance of the Version request
    -- @param host table as received by the action method
    -- @param port table as received by the action method
    -- @param lhost string containing the source IP
    -- @param lport number containing the source port
    -- @return o instance of Version
    new = function(self, host, port, lhost, lport)
      local o = {
        host = host,
        port = port,
        lhost= lhost,
        lport= lport,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the Version request to a string
    -- @return data as string
    __tostring = function(self)
      local magic = 0xD9B4BEF9
      local cmd = "version\0\0\0\0\0"
      local len = 85
      -- ver: 0.4.0
      local ver = 0x9c40

      -- NODE_NETWORK = 1
      local services = 1
      local timestamp = os.time()
      local ra = NetworkAddress:new(self.host, self.port)
      local sa = NetworkAddress:new(self.lhost, self.lport)
      local nodeid = openssl.rand_bytes(8)
      local useragent = "\0"
      local lastblock = 0

      -- Construct payload in order to calculate checksum for the header
      local payload = bin.pack("<ILLAAAAI", ver, services, timestamp,
        tostring(ra), tostring(sa), nodeid, useragent, lastblock)

      -- Checksum is first 4 bytes of sha256(sha256(payload))
      local checksum = openssl.digest("sha256", payload)
      checksum = openssl.digest("sha256", checksum)

      -- Construct the header without checksum
      local header = bin.pack("<IAI", magic, cmd, len)

      -- After 2012-02-20, version messages require checksums
      header = header .. checksum:sub(1,4)

      return header .. payload
    end,
  },

  -- The GetAddr request
  GetAddr = {

    -- Creates a new instance of the Version request
    -- @param host table as received by the action method
    -- @param port table as received by the action method
    -- @param lhost string containing the source IP
    -- @param lport number containing the source port
    -- @return o instance of Version
    new = function(self, host, port, lhost, lport)
      local o = {
        host = host,
        port = port,
        lhost= lhost,
        lport= lport,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the Version request to a string
    -- @return data as string
    __tostring = function(self)
      local magic = 0xD9B4BEF9
      local cmd = "getaddr\0\0\0\0\0"
      local len = 0
      local chksum = 0xe2e0f65d

      return bin.pack("<IAII", magic, cmd, len, chksum)
    end
  },

  VerAck = {

    new = function(self)
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    __tostring = function(self)
      return bin.pack("<IAII", 0xD9B4BEF9, "verack\0\0\0\0\0\0", 0, 0xe2e0f65d)
    end,

   },
 
  -- The pong message is sent in response to a ping message.
  Pong = {
    new = function(self)
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    __tostring = function(self)
      local magic = 0xD9B4BEF9
      local cmd = "pong\0\0\0\0\0\0\0\0"
      local len = 0
      local chksum = 0xe2e0f65d

      return bin.pack("<IAII", magic, cmd, len, chksum)
    end,
 
  }

}

-- The response class container
Response = {

  Header = {
    size = 24,
    new = function(self)
      local o = {
        magic = 0,
        cmd = "",
        length = 0,
        checksum = 0,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data)
      local header = Response.Header:new()
      local pos

      pos, header.magic, header.cmd, header.length, header.checksum = bin.unpack(">IA12II", data)
      return header
    end,
  },


  Alert = {

    type = "Alert",
    -- Creates a new instance of Version based on data string
    -- @param data string containing the raw response
    -- @return o instance of Version
    new = function(self, data)
      local o = {
        data = data,
      }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the Version instance
    parse = function(self)
      local pos = Response.Header.size + 1
      self.header = Response.Header.parse(self.data)

      local p_length
      pos, p_length = Util.decodeVarInt(self.data, pos)
      local data
      pos, data = bin.unpack("A" .. p_length, self.data, pos)

      --
      -- TODO: Alert decoding goes here
      --

      return
    end,
  },


  -- The version response message
  Version = {

    -- Creates a new instance of Version based on data string
    -- @param data string containing the raw response
    -- @return o instance of Version
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the Version instance
    parse = function(self)
      local pos, ra, sa

      -- After 2012-02-20, version messages contain checksums
      pos, self.magic, self.cmd, self.len, self.checksum, self.ver_raw, self.service,
        self.timestamp, ra, sa, self.nodeid,
        self.subver, self.lastblock = bin.unpack("<IA12IIILLA26A26H8CI", self.data)

      local function decode_bitcoin_version(n)
        if ( n < 31300 ) then
          local minor, micro = n // 100, n % 100
          return ("0.%d.%d"):format(minor, micro)
        else
          local minor, micro = n // 10000, (n // 100) % 100
          return ("0.%d.%d"):format(minor, micro)
        end
      end

      self.ver = decode_bitcoin_version(self.ver_raw)
      self.sa = NetworkAddress.fromString(sa)
      self.ra = NetworkAddress.fromString(ra)
    end,
  },

  -- The verack response message
  VerAck = {

    -- Creates a new instance of VerAck based on data string
    -- @param data string containing the raw response
    -- @return o instance of Version
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the VerAck instance
    parse = function(self)
      local pos
      -- After 2012-02-20, VerAck messages contain checksums
      pos, self.magic, self.cmd, self.checksum = bin.unpack("<IA12I", self.data)
    end,
  },

  -- The Addr response message
  Addr = {

    -- Creates a new instance of VerAck based on data string
    -- @param data string containing the raw response
    -- @return o instance of Addr
    new = function(self, data, version)
      local o = { data = data, version=version }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the Addr instance
    parse = function(self)
      local pos, count
      pos, self.magic, self.cmd, self.len, self.chksum = bin.unpack("<IA12II", self.data)
      pos, count = Util.decodeVarInt(self.data, pos)

      self.addresses = {}
      for c=1, count do
        if ( self.version > 31402 ) then
          local timestamp, data
          pos, timestamp, data = bin.unpack("<IA26", self.data, pos)
          local na = NetworkAddress.fromString(data)
          table.insert(self.addresses, { ts = timestamp, address = na })
        end
      end

    end,
  },

  -- The inventory server packet
  Inv = {

    -- Creates a new instance of VerAck based on data string
    -- @param data string containing the raw response
    -- @return o instance of Addr
    new = function(self, data, version)
      local o = { data = data, version=version }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the Addr instance
    parse = function(self)
      local pos, count
      pos, self.magic, self.cmd, self.len = bin.unpack("<IA12II", self.data)
    end,
  },

  -- Receives the packet and decodes it
  -- @param socket socket connected to the server
  -- @param version number containing the server version
  -- @return status true on success, false on failure
  -- @return response instance of response packet if status is true
  --         err string containing the error message if status is false
  recvPacket = function(socket, version)
    local status, header = socket:receive_buf(match.numbytes(24), true)
    if ( not(status) ) then
      return false, "Failed to read the packet header"
    end

    local pos, magic, cmd, len, checksum = bin.unpack("<IA12II", header)
    local data = ""

    -- the verack and ping has no payload
    if ( 0 ~= len ) then
      status, data = socket:receive_buf(match.numbytes(len), true)
      if ( not(status) ) then
        return false, "Failed to read the packet header"
      end
    else
      -- The ping message is sent primarily to confirm that the TCP/IP connection is still valid.
      if( cmd == "ping\0\0\0\0\0\0\0\0" ) then
        local req = Request.Pong:new()

        local status, err = socket:send(tostring(req))
        if ( not(status) ) then
          return false, "Failed to send \"Pong\" reply to server"
        else
          return Response.recvPacket(socket, version)
        end
      end
    end
    return Response.decode(header .. data, version)
  end,

  -- Decodes the raw packet data
  -- @param data string containing the raw packet
  -- @param version number containing the server version
  -- @return status true on success, false on failure
  -- @return response instance of response packet if status is true
  --         err string containing the error message if status is false
  decode = function(data, version)
    local pos, magic, cmd = bin.unpack("<IA12", data)
    if ( "version\0\0\0\0\0" == cmd ) then
      return true, Response.Version:new(data)
    elseif ( "verack\0\0\0\0\0\0" == cmd ) then
      return true, Response.VerAck:new(data)
    elseif ( "addr\0\0\0\0\0\0\0\0" == cmd ) then
      return true, Response.Addr:new(data, version)
    elseif ( "inv\0\0\0\0\0\0\0\0\0" == cmd ) then
      return true, Response.Inv:new(data)
    elseif ( "alert\0\0\0\0\0" == cmd ) then
      return true, Response.Alert:new(data)
    else
      return false, ("Unknown command (%s)"):format(cmd)
    end
  end,
}

Util = {

  -- Decodes a variable length int
  -- @param data string of data
  -- @param pos the location within the string to decode
  -- @return pos the new position
  -- @return count number the decoded argument
  decodeVarInt = function(data, pos)
    local pos, count = bin.unpack("C", data, pos)
    if ( count == 0xfd ) then
      return bin.unpack("<S", data, pos)
    elseif ( count == 0xfe ) then
      return bin.unpack("<I", data, pos)
    elseif ( count == 0xff ) then
      return bin.unpack("<L", data, pos)
    else
      return pos, count
    end
  end


}

-- The Helper class used as a primary interface to scripts
Helper = {

  -- Creates a new Helper instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param options table containing additional options
  --    <code>timeout</code> - the socket timeout in ms
  -- @return instance of Helper
  new = function(self, host, port, options)
    local o = {
      host = host,
      port = port,
      options = options or {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the BitCoin Server
  -- @return status true on success false on failure
  -- @return err string containing the error message in case status is false
  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 10000)
    local status, err = self.socket:connect(self.host, self.port)

    if ( not(status) ) then
      return false, err
    end
    status, self.lhost, self.lport = self.socket:get_info()
    return status, (status and nil or self.lhost)
  end,

  -- Performs a version handshake with the server
  -- @return status, true on success false on failure
  -- @return version instance if status is true
  --         err string containing an error message if status is false
  exchVersion = function(self)
    if ( not(self.socket) ) then
      return false
    end

    local req = Request.Version:new(
      self.host, self.port, self.lhost, self.lport
    )

    local status, err = self.socket:send(tostring(req))
    if ( not(status) ) then
      return false, "Failed to send \"Version\" request to server"
    end

    local version
    status, version = Response.recvPacket(self.socket)

    if ( not(status) or not(version) or version.cmd ~= "version\0\0\0\0\0" ) then
      return false, "Failed to read \"Version\" response from server"
    end

    if ( version.ver_raw > 29000 ) then
      local status, verack = Response.recvPacket(self.socket)
    end

    local verack = Request.VerAck:new()
    local status, err = self.socket:send(tostring(verack))
    if ( not(status) ) then
      return false, "Failed to send \"Version\" request to server"
    end

    self.version = version.ver_raw
    return status, version
  end,

  getNodes = function(self)
    local req = Request.GetAddr:new(
      self.host, self.port, self.lhost, self.lport
    )

    local status, err = self.socket:send(tostring(req))
    if ( not(status) ) then
      return false, "Failed to send \"Version\" request to server"
    end

    -- take care of any alerts that may be incoming
    local status, response = Response.recvPacket(self.socket, self.version)
    while ( status and response and response.type == "Alert" ) do
      status, response = Response.recvPacket(self.socket, self.version)
    end

    return status, response
  end,

  -- Reads a message from the server
  -- @return status true on success, false on failure
  -- @return response instance of response packet if status is true
  --         err string containing the error message if status is false
  readMessage = function(self)
    assert(self.version, "Version handshake has not been performed")
    return Response.recvPacket(self.socket, self.version)
  end,

  -- Closes the connection to the server
  -- @return status true on success false on failure
  -- @return err code, if status is false
  close = function(self)
    return self.socket:close()
  end
}

return _ENV;
