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
local unittest = require "unittest"
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

-- Bitcoin address validation and classification
-- Based on Base58Check (Bitcoin Wiki), BIP173, BIP350

-- Base58 alphabet (Bitcoin)
local BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

-- Bech32 character set (BIP173)
local BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- Bech32 polymod generator coefficients (BIP173)
local BECH32_GEN = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

-- Compute double SHA256 hash
-- @param data string of bytes
-- @return string of 32 bytes, or nil, err
local function doubleSha256(data)
  if not openssl then
    return nil, "openssl not available"
  end
  local hash = openssl.digest("sha256", data)
  return openssl.digest("sha256", hash)
end

-- Decode Base58 string to big-endian byte array
-- @param str base58 encoded string
-- @return table of bytes, or nil, error message
local function decodeBase58(str)
  local map = {}
  for i = 1, #BASE58_ALPHABET do
    map[BASE58_ALPHABET:sub(i, i)] = i - 1
  end

  -- Count leading 1s (= leading zero bytes)
  local leading = 0
  for i = 1, #str do
    if str:sub(i, i) ~= "1" then break end
    leading = leading + 1
  end

  if #str == 0 then
    return nil, "empty string"
  end

  -- Decode base58 into little-endian byte array
  local result = {0}
  for i = 1, #str do
    local c = str:sub(i, i)
    local carry = map[c]
    if not carry then
      return nil, "invalid character"
    end
    for j = 1, #result do
      carry = carry + result[j] * 58
      result[j] = carry & 0xff
      carry = carry >> 8
    end
    while carry > 0 do
      result[#result + 1] = carry & 0xff
      carry = carry >> 8
    end
  end

  -- Reverse to big-endian
  local out = {}
  for i = #result, 1, -1 do
    out[#out + 1] = result[i]
  end

  -- Prepend leading zeros
  for i = 1, leading do
    table.insert(out, 1, 0)
  end

  return out
end

-- Validate Base58Check encoded string
-- @param str base58 encoded string
-- @return table with payload (byte array), or nil, error
local function decodeBase58Check(str)
  if not openssl then
    return nil, "openssl not available"
  end

  local decoded, err = decodeBase58(str)
  if not decoded then
    return nil, err
  end

  if #decoded < 5 then
    return nil, "too short"
  end

  -- Split into payload (all but last 4) and checksum (last 4)
  local payloadLen = #decoded - 4
  local payloadBytes = {}
  for i = 1, payloadLen do
    payloadBytes[i] = decoded[i]
  end

  -- Build string and verify double-SHA256 checksum
  local payloadStr = string.char(table.unpack(payloadBytes, 1, payloadLen))
  local hash = doubleSha256(payloadStr)

  for i = 1, 4 do
    if hash:byte(i) ~= decoded[payloadLen + i] then
      return nil, "invalid checksum"
    end
  end

  return { payload = payloadBytes }
end

-- Expand HRP for Bech32 checksum (BIP173)
-- @param hrp string
-- @return table of 5-bit values
local function hrpExpand(hrp)
  local ret = {}
  for i = 1, #hrp do
    ret[#ret + 1] = hrp:byte(i) >> 5
  end
  ret[#ret + 1] = 0
  for i = 1, #hrp do
    ret[#ret + 1] = hrp:byte(i) & 31
  end
  return ret
end

-- Compute Bech32 polymod (BIP173/BIP350)
-- @param values table of 5-bit values
-- @return integer checksum
local function bech32Polymod(values)
  local chk = 1
  for _, v in ipairs(values) do
    local top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ~ v
    for i = 1, 5 do
      if (top >> (i - 1)) & 1 == 1 then
        chk = chk ~ BECH32_GEN[i]
      end
    end
  end
  return chk
end

-- Convert between bit widths
-- @param data table of source values
-- @param fromBits source bit width
-- @param toBits target bit width
-- @param pad whether to allow padding
-- @return table of converted values, or nil, error
local function convertBits(data, fromBits, toBits, pad)
  local ret = {}
  local acc = 0
  local bits = 0
  local maxv = (1 << toBits) - 1
  local maxAcc = (1 << (fromBits + toBits)) - 1
  for _, v in ipairs(data) do
    if v < 0 or (v >> fromBits) ~= 0 then
      return nil, "invalid value for bit width"
    end
    acc = ((acc << fromBits) | v) & maxAcc
    bits = bits + fromBits
    while bits >= toBits do
      bits = bits - toBits
      ret[#ret + 1] = (acc >> bits) & maxv
    end
  end
  if pad then
    if bits > 0 then
      ret[#ret + 1] = (acc << (toBits - bits)) & maxv
    end
  else
    if bits >= fromBits or ((acc << (toBits - bits)) & maxv) ~= 0 then
      return nil, "non-zero padding"
    end
  end
  return ret
end

-- Decode Bech32/Bech32m string (BIP173/BIP350)
-- @param str bech32 encoded string
-- @return table with hrp, witnessVersion, witnessProgram, encoding, or nil, error
local function decodeBech32(str)
  -- Find separator '1'
  local sep = str:find("1", 2, true)
  if not sep then
    return nil, "missing separator"
  end
  if sep < 2 or sep > #str - 7 then
    return nil, "invalid separator position"
  end

  local hrp = str:sub(1, sep - 1):lower()
  local dataPart = str:sub(sep + 1)

  if #dataPart < 7 then
    return nil, "data part too short"
  end

  -- Check for mixed case
  local lower = dataPart:lower()
  local upper = dataPart:upper()
  if dataPart ~= lower and dataPart ~= upper then
    return nil, "mixed case"
  end
  dataPart = lower

  -- Decode data characters to 5-bit values
  local values = {}
  for i = 1, #dataPart do
    local pos = BECH32_CHARSET:find(dataPart:sub(i, i), 1, true)
    if not pos then
      return nil, "invalid character"
    end
    values[#values + 1] = pos - 1
  end

  -- Verify checksum
  local checksumInput = hrpExpand(hrp)
  for _, v in ipairs(values) do
    checksumInput[#checksumInput + 1] = v
  end
  local polymod = bech32Polymod(checksumInput)

  local encoding
  if polymod == 1 then
    encoding = "bech32"
  elseif polymod == 0x2bc830a3 then
    encoding = "bech32m"
  else
    return nil, "invalid checksum"
  end

  -- Extract witness version and program (5-bit groups)
  local witnessVersion = values[1]
  if witnessVersion > 16 then
    return nil, "invalid witness version"
  end

  local witnessProgram5 = {}
  for i = 2, #values - 6 do
    witnessProgram5[#witnessProgram5 + 1] = values[i]
  end

  -- Convert witness program from 5-bit to 8-bit
  local witnessProgram8, err = convertBits(witnessProgram5, 5, 8, false)
  if not witnessProgram8 then
    return nil, "invalid witness program: " .. err
  end

  -- Validate based on witness version
  if witnessVersion == 0 then
    if encoding ~= "bech32" then
      return nil, "v0 witness must use Bech32, not Bech32m"
    end
    if #witnessProgram8 ~= 20 and #witnessProgram8 ~= 32 then
      return nil, "invalid witness program length for v0"
    end
  elseif witnessVersion >= 1 and witnessVersion <= 16 then
    if encoding ~= "bech32m" then
      return nil, string.format("v%d witness must use Bech32m", witnessVersion)
    end
    if #witnessProgram8 < 2 or #witnessProgram8 > 40 then
      return nil, "invalid witness program length for v1+"
    end
  end

  return {
    hrp = hrp,
    witnessVersion = witnessVersion,
    witnessProgram = witnessProgram8,
    encoding = encoding,
  }
end

--- Quick regex-based address candidate detection
-- @param value string to check
-- @return table with candidate, family, probable_network, probable_type
looks_like_address = function(value)
  if type(value) ~= "string" or #value == 0 then
    return { candidate = false }
  end

  -- Bech32 patterns
  if value:match("^[Bb][Cc]1") then
    return { candidate = true, family = "bech32", probable_network = "mainnet", probable_type = "segwit_or_taproot" }
  end
  if value:match("^[Tt][Bb]1") then
    return { candidate = true, family = "bech32", probable_network = "testnet", probable_type = "segwit_or_taproot" }
  end
  if value:match("^[Bb][Cc][Rr][Tt]1") then
    return { candidate = true, family = "bech32", probable_network = "regtest", probable_type = "segwit_or_taproot" }
  end

  -- Base58Check patterns
  local first = value:sub(1, 1)
  if first == "1" then
    return { candidate = true, family = "base58", probable_network = "mainnet", probable_type = "p2pkh" }
  end
  if first == "3" then
    return { candidate = true, family = "base58", probable_network = "mainnet", probable_type = "p2sh" }
  end
  if first == "m" or first == "n" then
    return { candidate = true, family = "base58", probable_network = "testnet", probable_type = "p2pkh" }
  end
  if first == "2" then
    return { candidate = true, family = "base58", probable_network = "testnet", probable_type = "p2sh" }
  end

  -- WIF patterns
  if first == "5" or first == "K" or first == "L" then
    return { candidate = true, family = "base58", probable_network = "mainnet", probable_type = "wif" }
  end
  if first == "9" or first == "c" then
    return { candidate = true, family = "base58", probable_network = "testnet", probable_type = "wif" }
  end

  -- Extended key patterns
  if value:match("^[xX][pP][uU][bB]") then
    return { candidate = true, family = "base58", probable_network = "mainnet", probable_type = "xpub" }
  end
  if value:match("^[xX][pP][rR][vV]") then
    return { candidate = true, family = "base58", probable_network = "mainnet", probable_type = "xprv" }
  end
  if value:match("^[tT][pP][uU][bB]") then
    return { candidate = true, family = "base58", probable_network = "testnet", probable_type = "xpub" }
  end
  if value:match("^[tT][pP][rR][vV]") then
    return { candidate = true, family = "base58", probable_network = "testnet", probable_type = "xprv" }
  end

  return { candidate = false }
end

--- Full cryptographic address validation
-- @param value string to validate
-- @return table with valid, network, type, encoding, witnessVersion, reason
validate_address = function(value)
  if type(value) ~= "string" or #value == 0 then
    return { valid = false, reason = "empty or non-string" }
  end

  -- Try Bech32/Bech32m for addresses starting with known HRPs
  local lower = value:lower()
  if lower:sub(1, 4) == "bcrt" or lower:sub(1, 2) == "bc" or lower:sub(1, 2) == "tb" then
    local result, err = decodeBech32(value)
    if not result then
      return { valid = false, encoding = "bech32", reason = err }
    end
    local network
    if result.hrp == "bc" then
      network = "mainnet"
    elseif result.hrp == "tb" then
      network = "testnet"
    elseif result.hrp == "bcrt" then
      network = "regtest"
    else
      network = "unknown"
    end
    local addrType
    if result.witnessVersion == 0 then
      if #result.witnessProgram == 20 then
        addrType = "p2wpkh"
      elseif #result.witnessProgram == 32 then
        addrType = "p2wsh"
      else
        addrType = "segwit_v0"
      end
    elseif result.witnessVersion == 1 then
      addrType = "p2tr"
    else
      addrType = "witness_v1_plus"
    end
    return {
      valid = true,
      network = network,
      type = addrType,
      encoding = result.encoding,
      witnessVersion = result.witnessVersion,
      reason = "ok",
    }
  end

  -- Try Base58Check
  local result, err = decodeBase58Check(value)
  if not result then
    return { valid = false, encoding = "base58check", reason = err or "invalid" }
  end

  local payload = result.payload
  if #payload < 1 then
    return { valid = false, encoding = "base58check", reason = "empty payload" }
  end

  -- Check for 4-byte version prefixes (extended keys)
  if #payload >= 4 then
    local v4 = (payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]
    if v4 == 0x0488B21E then
      return { valid = true, network = "mainnet", type = "xpub", encoding = "base58check", reason = "ok" }
    end
    if v4 == 0x0488ADE4 then
      return { valid = true, network = "mainnet", type = "xprv", encoding = "base58check", reason = "ok" }
    end
    if v4 == 0x043587CF then
      return { valid = true, network = "testnet", type = "xpub", encoding = "base58check", reason = "ok" }
    end
    if v4 == 0x04358394 then
      return { valid = true, network = "testnet", type = "xprv", encoding = "base58check", reason = "ok" }
    end
  end

  -- Check single-byte version prefixes
  local v = payload[1]
  if v == 0x00 then
    return { valid = true, network = "mainnet", type = "p2pkh", encoding = "base58check", reason = "ok" }
  end
  if v == 0x05 then
    return { valid = true, network = "mainnet", type = "p2sh", encoding = "base58check", reason = "ok" }
  end
  if v == 0x6f then
    return { valid = true, network = "testnet", type = "p2pkh", encoding = "base58check", reason = "ok" }
  end
  if v == 0xc4 then
    return { valid = true, network = "testnet", type = "p2sh", encoding = "base58check", reason = "ok" }
  end
  if v == 0x80 then
    local net = (value:sub(1, 1) == "9" or value:sub(1, 1) == "c") and "testnet" or "mainnet"
    return { valid = true, network = net, type = "wif", encoding = "base58check", reason = "ok" }
  end

  return { valid = true, network = "unknown", type = "unknown", encoding = "base58check", reason = "unknown version byte" }
end

--- High-level address classification uses regex detection then full validation
-- @param value string to classify
-- @return table with valid, network, type, encoding, reason
classify_address = function(value)
  local quick = looks_like_address(value)
  if not quick.candidate then
    return { valid = false, reason = "not a recognized address format" }
  end
  return validate_address(value)
end

if not unittest.testing() then
  return _ENV
end

-- Test vectors (public/synthetic - no real keys with funds)
test_suite = unittest.TestSuite:new()

-- Mainnet Base58Check valid addresses
local r1 = classify_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
test_suite:add_test(unittest.is_true(r1.valid), "mainnet P2PKH (genesis) valid")
test_suite:add_test(unittest.equal(r1.network, "mainnet"), "genesis network mainnet")
test_suite:add_test(unittest.equal(r1.type, "p2pkh"), "genesis type p2pkh")

local r2 = classify_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
test_suite:add_test(unittest.is_true(r2.valid), "mainnet P2SH valid")
test_suite:add_test(unittest.equal(r2.network, "mainnet"), "P2SH network mainnet")
test_suite:add_test(unittest.equal(r2.type, "p2sh"), "P2SH type p2sh")

-- Mainnet Bech32m P2TR (BIP350)
local r3 = classify_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
test_suite:add_test(unittest.is_true(r3.valid), "mainnet P2TR (BIP350) valid")
test_suite:add_test(unittest.equal(r3.network, "mainnet"), "P2TR network mainnet")
test_suite:add_test(unittest.equal(r3.type, "p2tr"), "P2TR type")

-- Testnet Bech32m P2TR (BIP350)
local r4 = classify_address("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
test_suite:add_test(unittest.is_true(r4.valid), "testnet P2TR (BIP350) valid")
test_suite:add_test(unittest.equal(r4.network, "testnet"), "testnet P2TR network")
test_suite:add_test(unittest.equal(r4.type, "p2tr"), "testnet P2TR type")

-- Mainnet Bech32 (BIP173 P2WPKH)
local r5 = classify_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
test_suite:add_test(unittest.is_true(r5.valid), "mainnet P2WPKH (BIP173) valid")
test_suite:add_test(unittest.equal(r5.network, "mainnet"), "P2WPKH network mainnet")
test_suite:add_test(unittest.equal(r5.type, "p2wpkh"), "P2WPKH type")

-- Mainnet Bech32m v1 P2WSH (BIP350)
local r6 = classify_address("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")
test_suite:add_test(unittest.is_true(r6.valid), "mainnet v1 P2WSH (BIP350) valid")
test_suite:add_test(unittest.equal(r6.network, "mainnet"), "v1 P2WSH network mainnet")

-- Testnet Bech32 (BIP173 P2WSH)
local r7 = classify_address("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
test_suite:add_test(unittest.is_true(r7.valid), "testnet P2WSH (BIP173) valid")
test_suite:add_test(unittest.equal(r7.network, "testnet"), "testnet P2WSH network")
test_suite:add_test(unittest.equal(r7.type, "p2wsh"), "testnet P2WSH type")

-- Mainnet Bech32m v2 (BIP350)
local r8 = classify_address("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")
test_suite:add_test(unittest.is_true(r8.valid), "mainnet v2 Bech32m (BIP350) valid")
test_suite:add_test(unittest.equal(r8.network, "mainnet"), "v2 network")
test_suite:add_test(unittest.equal(r8.type, "witness_v1_plus"), "v2 type")

-- Invalid addresses
local r9 = validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
test_suite:add_test(unittest.is_false(r9.valid), "broken Base58 checksum invalid")

local r10 = validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
test_suite:add_test(unittest.is_false(r10.valid), "broken Bech32 checksum invalid")

local r11 = validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tQ")
test_suite:add_test(unittest.is_false(r11.valid), "mixed case Bech32 invalid")

local r12 = validate_address("bc1q")
test_suite:add_test(unittest.is_false(r12.valid), "too short Bech32 invalid")

-- Invalid Bech32m (v0 address decoded as Bech32m fails, but here we use a BIP350 invalid test)
local r12b = validate_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd")
test_suite:add_test(unittest.is_false(r12b.valid), "Bech32m invalid checksum")

-- Regex detection tests
local r13 = looks_like_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
test_suite:add_test(unittest.is_true(r13.candidate), "looks_like mainnet P2PKH")
test_suite:add_test(unittest.equal(r13.family, "base58"), "looks_like family base58")
test_suite:add_test(unittest.equal(r13.probable_network, "mainnet"), "looks_like network mainnet")
test_suite:add_test(unittest.equal(r13.probable_type, "p2pkh"), "looks_like type p2pkh")

local r14 = looks_like_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
test_suite:add_test(unittest.is_true(r14.candidate), "looks_like Bech32")
test_suite:add_test(unittest.equal(r14.family, "bech32"), "looks_like family bech32")

local r15 = looks_like_address("random text that is not an address")
test_suite:add_test(unittest.is_false(r15.candidate), "random text not a candidate")

-- Regtest detection
local r16 = looks_like_address("bcrt1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
test_suite:add_test(unittest.is_true(r16.candidate), "looks_like regtest Bech32")
test_suite:add_test(unittest.equal(r16.probable_network, "regtest"), "looks_like regtest network")

-- classify_address on non-address
local r17 = classify_address("not an address")
test_suite:add_test(unittest.is_false(r17.valid), "classify non-address invalid")

return _ENV;
