---
-- The AMQP library provides some basic functionality for retrieving information
-- about an AMQP server's properties.
--
-- Summary
-- -------
-- The library currently supports the AMQP 0-9 and 0-8 protocol specifications.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--  o AMQP
--    - This class contains the core functions needed to communicate with AMQP
--
-- @args amqp.version Can be used to specify the client version to use (currently, 0-8, 0-9 or 0-9-1)
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Sebastian Dragomir <velorien@gmail.com>

-- Version 0.1

-- Created 05/04/2011 - v0.1 - created by Sebastian Dragomir <velorien@gmail.com>

local bin = require "bin"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("amqp", stdnse.seeall);


AMQP = {

  -- protocol versions sent by the server
  versions = {
    [0x0800] = "0-8",
    [0x0009] = "0-9"
  },

  -- version strings the client supports
  client_version_strings = {
    ["0-8"] = "\x01\x01\x08\x00",
    ["0-9"] = "\x00\x00\x09\x00",
    ["0-9-1"] = "\x00\x00\x09\x01"
  },

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.amqpsocket = nmap.new_socket()
    o.cli_version = self.client_version_strings[nmap.registry.args['amqp.version']] or self.client_version_strings["0-9-1"]
    o.protover = nil
    o.server_version = nil
    o.server_product = nil
    o.serer_properties = nil
    return o
  end,

  --- Connects the AMQP socket
  connect = function(self)
    local data, status, msg

    status, msg = self.amqpsocket:connect(self.host, self.port, "tcp")
    return status, msg
  end,

  --- Disconnects the AMQP socket
  disconnect = function(self)
    self.amqpsocket:close()
  end,

  --- Decodes a table value in the server properties field.
  --
  -- @param tbl the decoded table
  -- @param tsize number, the table size in bytes
  -- @return status, true on success, false on failure
  -- @return error string containing error message if status is false
  -- @return decoded value
  decodeTable = function(self, tbl, tsize)
    local status, err, tmp, read, value
    read = 0

    while read < tsize do
      local key, value

      status, tmp = self.amqpsocket:receive_buf(match.numbytes(1), true)
      if ( not(status) ) then
        return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading key length", nil
      end
      read = read + 1

      tmp = select( 2, bin.unpack("C", tmp) )
      status, key = self.amqpsocket:receive_buf(match.numbytes(tmp), true)
      if ( not(status) ) then
        return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading key", nil
      end
      read = read + tmp

      status, tmp = self.amqpsocket:receive_buf(match.numbytes(1), true)
      if ( not(status) ) then
        return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading value type for " .. key, nil
      end
      read = read + 1

      if ( tmp == 'F' ) then -- table type
        status, tmp = self.amqpsocket:receive_buf(match.numbytes(4), true)
        if ( not(status) ) then
          return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading table size", nil
        end

        read = read + 4
        value = {}
        tmp = select( 2, bin.unpack(">I", tmp) )
        status, err, value = self:decodeTable(value, tmp)
        read = read + tmp
        table.insert(tbl, key .. ": ")
        table.insert(tbl, value)
      elseif ( tmp == 'S' ) then -- string type
        status, err, value, read = self:decodeString(key, read)
        if ( key == "product" ) then
          self.server_product = value
        elseif ( key == "version" ) then
          self.server_version = value
        end
        table.insert(tbl, key .. ": " .. value)
      elseif ( tmp == 't' ) then -- boolean type
        status, err, value, read = self:decodeBoolean(key, read)
        table.insert(tbl, key .. ": " .. value)
      end

      if ( not(status) ) then
        return status, err, nil
      end

    end

    return true, nil, tbl
  end,

  --- Decodes a string value in the server properties field.
  --
  -- @param key string, the key being read
  -- @param read number, number of bytes already read
  -- @return status, true on success, false on failure
  -- @return error string containing error message if status is false
  -- @return decoded value
  -- @return number of bytes read after decoding this value
  decodeString = function(self, key, read)
    local value, status, tmp
    status, tmp = self.amqpsocket:receive_buf(match.numbytes(4), true)
    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading value size for " .. key, nil, 0
    end

    read = read + 4
    tmp = select( 2, bin.unpack(">I", tmp) )
    status, value = self.amqpsocket:receive_buf(match.numbytes(tmp), true)

    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading value for " .. key, nil, 0
    end
    read = read + tmp

    return true, nil, value, read
  end,

  --- Decodes a boolean value in the server properties field.
  --
  -- @param key string, the key being read
  -- @param read number, number of bytes already read
  -- @return status, true on success, false on failure
  -- @return error string containing error message if status is false
  -- @return decoded value
  -- @return number of bytes read after decoding this value
  decodeBoolean = function(self, key, read)
    local status, value
    status, value = self.amqpsocket:receive_buf(match.numbytes(1), true)
    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading value for " .. key, nil, 0
    end

    value = select( 2, bin.unpack("C", value) )
    read = read + 1

    return true, nil, value == 0x01 and "YES" or "NO", read
  end,

  --- Performs the AMQP handshake and determines
  -- * The AMQP protocol version
  -- * The server properties/capabilities
  --
  -- @return status, true on success, false on failure
  -- @return error string containing error message if status is false
  handshake = function(self)
    local _, status, err, version, tmp, value, properties

    status = self.amqpsocket:send( "AMQP" .. self.cli_version )
    if ( not(status) ) then
      return false, "ERROR: AMQP:handshake failed while sending client version"
    end

    status, tmp = self.amqpsocket:receive_buf(match.numbytes(11), true)
    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading frame header"
    end

    -- check if the server rejected our proposed version
    if ( #tmp ~= 11 ) then
      if ( #tmp == 8 and select( 2, bin.unpack(">I", tmp) ) == 0x414D5150 ) then
        local vi, vii, v1, v2, v3, v4, found
        _, vi = bin.unpack(">I", tmp, 5)
        found = false

        -- check if we support the server's version
        for _, v in pairs( self.client_version_strings ) do
          _, vii = bin.unpack(">I", v)
          if ( vii == vi ) then
            version = v
            found = true
            break
          end
        end

        -- try again with new version string
        if ( found and version ~= self.cli_version ) then
          self.cli_version = version
          self:disconnect()
          status, err = self:connect()

          if ( not(status) ) then
            return status, err
          end

          return self:handshake()
        end

        -- version unsupported
        _, v1, v2, v3, v4 = bin.unpack(">CCCC", tmp, 5)
        return false, ("ERROR: AMQP:handshake unsupported version (%d.%d.%d.%d)"):format( v1, v2, v3, v4 )
      else
        return false, ("ERROR: AMQP:handshake server might not be AMQP, received: %s"):format( tmp )
      end
    end

    -- parse frame header
    local frametype, chnumber, framesize, method
    _, frametype, chnumber, framesize, method = bin.unpack(">CSII", tmp)
    stdnse.debug1("frametype: %d, chnumber: %d, framesize: %d, method: %d", frametype, chnumber, framesize, method)

    if (frametype ~= 1) then
      return false, ("ERROR: AQMP:handshake expected header (1) frame, but was %d"):format(frametype)
    end

    if (method ~= 0x000A000A) then
      return false, ("ERROR: AQMP:handshake expected connection.start (0x000A000A) method, but was %x"):format(method)
    end

    -- parse protocol version
    status, tmp = self.amqpsocket:receive_buf(match.numbytes(2), true)
    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading version"
    end
    version = select( 2, bin.unpack(">S", tmp) )
    self.protover = AMQP.versions[version]

    if ( not(self.protover) ) then
      return false, ("ERROR: AMQP:handshake unsupported version (%x)"):format(version)
    end

    -- parse server properties
    status, tmp = self.amqpsocket:receive_buf(match.numbytes(4), true)
    if ( not(status) ) then
      return status, "ERROR: AMQP:handshake connection closed unexpectedly while reading server properties size"
    end

    local tablesize = select( 2, bin.unpack(">I", tmp) )
    properties = {}
    status, err, properties = self:decodeTable(properties, tablesize)

    if ( not(status) ) then
      return status, err
    end

    status, err, value, tmp = self:decodeString("mechanisms", 0)
    if ( not(status) ) then
      return status, err
    end
    table.insert(properties, "mechanisms: " .. value)

    status, err, value, tmp = self:decodeString("locales", 0)
    if ( not(status) ) then
      return status, err
    end
    table.insert(properties, "locales: " .. value)

    self.server_properties = properties

    return true
  end,

  --- Returns the protocol version reported by the server
  --
  -- @return string containing the version number
  getProtocolVersion = function( self )
    return self.protover
  end,

  --- Returns the product version reported by the server
  --
  -- @return string containing the version number
  getServerVersion = function( self )
    return self.server_version
  end,

  --- Returns the product name reported by the server
  --
  -- @return string containing the product name
  getServerProduct = function( self )
    return self.server_product
  end,

  --- Returns the properties reported by the server
  --
  -- @return table containing server properties
  getServerProperties = function( self )
    return self.server_properties
  end,
}

return _ENV;
