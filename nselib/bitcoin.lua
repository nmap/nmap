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

local ipOps = require "ipOps"
local match = require "match"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
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
    local ipv6_prefix, ipv4_addr
    na.service, ipv6_prefix, ipv4_addr, na.port = string.unpack("<I8 c12 c4 >I2", data)
    if ipv6_prefix == "\0\0\0\0\0\0\0\0\0\0\xff\xff" then
      -- IPv4
      na.host = ipOps.str_to_ip(ipv4_addr)
    else
      na.host = ipOps.str_to_ip(ipv6_prefix .. ipv4_addr)
    end
    return na
  end,

  -- Converts the NetworkAddress instance to string
  -- @return data string containing the NetworkAddress instance
  __tostring = function(self)
    local ipv6_addr = ipOps.ip_to_str(self.host)
    return string.pack("<I8 c16 >I2", self.service, ipv6_addr, self.port )
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
      local cmd = "version"
      local len = 85
      -- ver: 0.4.0
      local ver = 0x9c40

      cmd = cmd .. ('\0'):rep(12 - #cmd)

      -- NODE_NETWORK = 1
      local services = 1
      local timestamp = os.time()
      local ra = NetworkAddress:new(self.host, self.port)
      local sa = NetworkAddress:new(self.lhost, self.lport)
      local nodeid = openssl.rand_bytes(8)
      local useragent = "\0"
      local lastblock = "\0\0\0\0"

      -- Construct payload in order to calculate checksum for the header
      local payload = (string.pack("<I4 I8 I8", ver, services, timestamp)
        .. tostring(ra) .. tostring(sa) .. nodeid .. useragent .. lastblock)

      -- Checksum is first 4 bytes of sha256(sha256(payload))
      local checksum = openssl.digest("sha256", payload)
      checksum = openssl.digest("sha256", checksum)

      -- Construct the header without checksum
      local header = string.pack("<I4 c12 I4", magic, cmd, len)

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
      local cmd = "getaddr"
      local len = 0
      local chksum = 0xe2e0f65d
      cmd = cmd .. ('\0'):rep(12 - #cmd)

      return string.pack("<I4 c12 I4 I4", magic, cmd, len, chksum)
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
      local cmd = "verack"
      cmd = cmd .. ('\0'):rep(12 - #cmd)
      return string.pack("<I4 c12 I4 I4", 0xD9B4BEF9, cmd, 0, 0xe2e0f65d)
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
      local cmd = "pong"
      local len = 0
      local chksum = 0xe2e0f65d
      cmd = cmd .. ('\0'):rep(12 - #cmd)

      return string.pack("<I4 c12 I4 I4", magic, cmd, len, chksum)
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

      local cmd
      header.magic, cmd, header.length, header.checksum = string.unpack(">I4 c12 I4 I4", data)
      header.cmd = string.unpack("z", cmd)
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

      local data
      pos, data = Util.decodeVarString(self.data, pos)

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
      local ra, sa, cmd, nodeid, pos

      -- After 2012-02-20, version messages contain checksums
      self.magic, cmd, self.len, self.checksum, self.ver_raw, self.service,
        self.timestamp, ra, sa, nodeid,
        pos = string.unpack("<I4 c12 I4 I4 I4 I8 I8 c26 c26 c8", self.data)
      pos, self.user_agent = Util.decodeVarString(self.data, pos)
      self.lastblock, pos = string.unpack("<I4", self.data, pos)
      self.nodeid = stdnse.tohex(nodeid)
      self.cmd = string.unpack("z", cmd)

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
      local cmd
      -- After 2012-02-20, VerAck messages contain checksums
      self.magic, cmd, self.checksum = string.unpack("<I4 c12 I4", self.data)
      self.cmd = string.unpack("z", cmd)
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
      local cmd
      self.magic, cmd, self.len, self.chksum, pos = string.unpack("<I4 c12 I4 I4", self.data)
      self.cmd = string.unpack("z", cmd)
      pos, count = Util.decodeVarInt(self.data, pos)

      self.addresses = {}
      for c=1, count do
        if ( self.version > 31402 ) then
          local timestamp, data
          timestamp, data, pos = string.unpack("<I4 c26", self.data, pos)
          local na = NetworkAddress.fromString(data)
          table.insert(self.addresses, { ts = timestamp, address = na })
        end
      end

    end,
  },

  -- The inventory server packet
  Inv = {

    -- Creates a new instance of Inv based on data string
    -- @param data string containing the raw response
    -- @return o instance of Inv
    new = function(self, data, version)
      local o = { data = data, version=version }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the raw data and builds the Inv instance
    parse = function(self)
      local cmd
      self.magic, cmd, self.len, self.chksum = string.unpack("<I4 c12 I4 I4", self.data)
      self.cmd = string.unpack("z", cmd)
      -- TODO parse inv_vect
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

    local magic, cmd, len, checksum = string.unpack("<I4 c12 I4 I4", header)
    local data = ""
    cmd = string.unpack("z", cmd)

    -- the verack and ping has no payload
    if ( 0 ~= len ) then
      status, data = socket:receive_buf(match.numbytes(len), true)
      if ( not(status) ) then
        return false, "Failed to read the packet header"
      end
    else
      -- The ping message is sent primarily to confirm that the TCP/IP connection is still valid.
      if( cmd == "ping" ) then
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
    local magic, cmd = string.unpack("<I4 z", data)
    if ( "version" == cmd ) then
      return true, Response.Version:new(data)
    elseif ( "verack" == cmd ) then
      return true, Response.VerAck:new(data)
    elseif ( "addr" == cmd ) then
      return true, Response.Addr:new(data, version)
    elseif ( "inv" == cmd ) then
      return true, Response.Inv:new(data)
    elseif ( "alert" == cmd ) then
      return true, Response.Alert:new(data)
    else
      return true, ("Unknown command (%s)"):format(cmd)
    end
  end,
}

Util = {

  varIntLen = {
    [0xfd] = 2,
    [0xfe] = 4,
    [0xff] = 8,
  },

  -- Decodes a variable length int
  -- @param data string of data
  -- @param pos the location within the string to decode
  -- @return pos the new position
  -- @return count number the decoded argument
  decodeVarInt = function(data, pos)
    local count, pos = string.unpack("B", data, pos)
    if count >= 0xfd then
      count, pos = string.unpack("<I" .. Util.varIntLen[count], data, pos)
    end
    return pos, count
  end,

  decodeVarString = function(data, pos)
    local count, pos = string.unpack("B", data, pos)
    local str
    if count < 0xfd then
      str, pos = string.unpack("s1", data, pos - 1)
    else
      str, pos = string.unpack("<s" .. Util.varIntLen[count], data, pos)
    end
    return pos, str
  end,

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

    if not status or not version then
      return false, "Failed to read \"Version\" response from server: " .. (version or "nil")
    elseif version.cmd ~= "version"  then
      return false, ('"Version" request got %s from server'):format(version.cmd)
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
      return false, "Failed to send \"GetAddr\" request to server"
    end

    local status, response = Response.recvPacket(self.socket, self.version)
    local all_addrs = {}
    local limit = 10
    -- Usually sends an addr response with 1 address,
    -- then some other stuff like getheaders or ping,
    -- then one with hundreds of addrs.
    while status and #all_addrs <= 1 and limit > 0 do
      limit = limit - 1
      status, response = Response.recvPacket(self.socket, self.version)
      if status and response.cmd == "addr" then
        for _, addr in ipairs(response.addresses) do
          all_addrs[#all_addrs+1] = addr
        end
      end
    end

    return #all_addrs > 0, all_addrs
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
