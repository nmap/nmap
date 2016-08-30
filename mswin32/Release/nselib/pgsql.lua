---
-- PostgreSQL library supporting both version 2 and version 3 of the protocol.
-- The library currently contains the bare minimum to perform authentication.
-- Authentication is supported with or without SSL enabled and using the
-- plain-text or MD5 authentication mechanisms.
--
-- The PGSQL protocol is explained in detail in the following references.
-- * http://developer.postgresql.org/pgdocs/postgres/protocol.html
-- * http://developer.postgresql.org/pgdocs/postgres/protocol-flow.html
-- * http://developer.postgresql.org/pgdocs/postgres/protocol-message-formats.html
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>

local bin = require "bin"
local nmap = require "nmap"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("pgsql", stdnse.seeall)

-- Version 0.3
-- Created 02/05/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/20/2010 - v0.2 - added detectVersion to automatically detect and return
--                             the correct version class
-- Revised 03/04/2010 - v0.3 - added support for trust authentication method

--- Supported pgsql message types
MessageType = {
  Error = 0x45,
  BackendKeyData = 0x4b,
  AuthRequest=0x52,
  ParameterStatus = 0x53,
  ReadyForQuery = 0x5a,
  PasswordMessage = 0x70,
}

--- Supported authentication types
AuthenticationType = {
  Success = 0x00,
  Plain = 0x03,
  MD5 = 0x05
}

-- Version 2 of the protocol
v2 =
{

  --- Pad a string with zeroes
  --
  -- @param str string containing the string to be padded
  -- @param len number containing the wanted length
  -- @return string containing the padded string value
  zeroPad = function(str, len)
    return str .. string.rep('\0', len - #str)
  end,

  messageDecoder = {

    --- Decodes an Auth Request packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding, -1 on error
    -- @return response table containing zero or more of the following <code>salt</code> and <code>success</code>
    --         error string containing error message if pos is -1
    [MessageType.AuthRequest] = function( data, len, pos )
      local _, authtype
      local response = {}
      pos, authtype = bin.unpack(">I", data, pos)

      if ( authtype == AuthenticationType.MD5 ) then
        if  ( len - pos + 1 ) < 3 then
          return -1, "ERROR: Malformed AuthRequest received"
        end
        pos, response.salt = bin.unpack("A4", data, pos)
      elseif ( authtype == AuthenticationType.Plain ) then
        --do nothing
      elseif ( authtype == 0 ) then
        response.success = true
      else
        stdnse.debug1("unknown auth type: %d", authtype)
      end

      response.authtype = authtype
      return pos, response
    end,



    --- Decodes an Error packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding
    -- @return response table containing zero or more of the following <code>error.severity</code>,
    -- <code>error.code</code>, <code>error.message</code>, <code>error.file</code>,
    -- <code>error.line</code> and <code>error.routine</code>
    [MessageType.Error] = function( data, len, pos )
      local tmp = data:sub(pos, pos + len - 4)
      local response = {}
      local pos_end = pos + len

      response.error = {}
      pos, response.error.message = bin.unpack("z", data, pos)
      return pos, response
    end,

  },

  --- Process the server response
  --
  -- @param data string containing the server response
  -- @param pos number containing the offset into the data buffer
  processResponse = function(data, pos)
    local ptype, len, status, response
    local pos = pos or 1

    pos, ptype = bin.unpack("C", data, pos)
    len = data:len() - 1

    if v2.messageDecoder[ptype] then
      pos, response = v2.messageDecoder[ptype](data, len, pos)

      if pos ~= -1 then
        response.type = ptype
        return pos, response
      end
    else
      stdnse.debug1("Missing decoder for %d", ptype)
      return -1, ("Missing decoder for %d"):format(ptype)
    end
    return -1, "Decoding failed"
  end,


  --- Reads a packet and handles additional socket reads to retrieve remaining data
  --
  -- @param socket socket already connected to the pgsql server
  -- @param data string containing any data already retrieved from the socket
  -- @param pos number containing the offset into the data buffer
  -- @return data string containing the initial and any additional data
  readPacket=function(socket, data, pos)

    local pos = pos or 1
    local data = data or ""
    local status = true
    local tmp = ""
    local ptype, len

    local catch = function() socket:close() stdnse.debug1("processResponse(): failed") end
    local try = nmap.new_try(catch)

    if ( data == nil or data:len() == 0 ) then
      data = try(socket:receive())
    end
    return data
  end,

  --- Sends a startup message to the server containing the username and database to connect to
  --
  -- @param socket socket already connected to the pgsql server
  -- @param user string containing the name of the user
  -- @param database string containing the name of the database
  -- @return status true on success, false on failure
  -- @return table containing a processed response from <code>processResponse</code>
  --         string containing error message if status is false
  sendStartup=function(socket, user, database)
    local data, response, status, pos
    local proto_ver, ptype, _, tmp

    local tty, unused, args = "", "", ""
    proto_ver = 0x0020000
    user = v2.zeroPad(user, 32)
    database = v2.zeroPad(database, 64)
    data = bin.pack(">I>IAAAAA", 296, proto_ver, database, user, v2.zeroPad(args, 64), v2.zeroPad(unused, 64), v2.zeroPad(tty,64) )

    socket:send( data )

    -- attempt to verify version
    status, data = socket:receive_bytes( 1 )

    if ( not(status) ) then
      return false, "sendStartup failed"
    end

    data = v2.readPacket(socket, data )
    pos, response = v2.processResponse( data )

    if ( pos < 0 or response.type == MessageType.Error) then
      return false, response.error.message or "unknown error"
    end

    return true, response
  end,

  --- Attempts to authenticate to the pgsql server
  -- Supports plain-text and MD5 authentication
  --
  -- @param socket socket already connected to the pgsql server
  -- @param params table containing any additional parameters <code>authtype</code>, <code>version</code>
  -- @param username string containing the username to use for authentication
  -- @param password string containing the password to use for authentication
  -- @param salt string containing the cryptographic salt value
  -- @return status true on success, false on failure
  -- @return result table containing parameter status information,
  --         result string containing an error message if login fails
  loginRequest = function ( socket, params, username, password, salt )

    local catch = function() socket:close() stdnse.debug1("loginRequest(): failed") end
    local try = nmap.new_try(catch)
    local response = {}
    local status, data, len, pos, tmp

    if ( params.authtype == AuthenticationType.MD5 ) then
      local hash = createMD5LoginHash(username,password,salt)
      data = bin.pack( ">Iz", 40, hash)
      try( socket:send( data ) )
    elseif ( params.authtype == AuthenticationType.Plain ) then
      local data
      data = bin.pack(">Iz", password:len() + 4, password)
      try( socket:send( data ) )
    elseif ( params.authtype == AuthenticationType.Success ) then
      return true, nil
    end

    data, response.params = "", {}

    data = v2.readPacket(socket, data, 1)
    pos, tmp = v2.processResponse(data, 1)

    -- this should contain the AuthRequest packet
    if tmp.type ~= MessageType.AuthRequest then
      return false, "Expected AuthRequest got something else"
    end

    if not tmp.success then
      return false, "Login failure"
    end

    return true, response
  end,

}

-- Version 3 of the protocol
v3 =
{
  messageDecoder = {

    --- Decodes an Auth Request packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding, -1 on error
    -- @return response table containing zero or more of the following <code>salt</code> and <code>success</code>
    --         error string containing error message if pos is -1
    [MessageType.AuthRequest] = function( data, len, pos )
      local _, authtype
      local response = {}

      pos, authtype = bin.unpack(">I", data, pos)

      if ( authtype == AuthenticationType.MD5 ) then
        if  ( len - pos + 1 ) < 3 then
          return -1, "ERROR: Malformed AuthRequest received"
        end
        pos, response.salt = bin.unpack("A4", data, pos)
      elseif ( authtype == AuthenticationType.Plain ) then
        --do nothing
      elseif ( authtype == 0 ) then
        response.success = true
      else
        stdnse.debug1("unknown auth type: %d", authtype )
      end

      response.authtype = authtype
      return pos, response
    end,

    --- Decodes an ParameterStatus packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding
    -- @return response table containing zero or more of the following <code>key</code> and <code>value</code>
    [MessageType.ParameterStatus] = function( data, len, pos )
      local tmp, _
      local response = {}

      tmp = data:sub(pos, pos + len - 4)
      _, response.key, response.value = bin.unpack("zz", tmp)
      return pos + len - 4, response
    end,

    --- Decodes an Error packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding
    -- @return response table containing zero or more of the following <code>error.severity</code>,
    -- <code>error.code</code>, <code>error.message</code>, <code>error.file</code>,
    -- <code>error.line</code> and <code>error.routine</code>
    [MessageType.Error] = function( data, len, pos )
      local tmp = data:sub(pos, pos + len - 4)
      local _, value, prefix
      local response = {}
      local pos_end = pos + len

      response.error = {}

      while ( pos < pos_end - 5 ) do
        pos, prefix, value = bin.unpack("Az", data, pos)

        if prefix == 'S' then
          response.error.severity = value
        elseif prefix == 'C' then
          response.error.code = value
        elseif prefix == 'M' then
          response.error.message = value
        elseif prefix == 'F' then
          response.error.file = value
        elseif prefix == 'L' then
          response.error.line = value
        elseif prefix == 'R' then
          response.error.routine = value
        end
      end
      return pos, response
    end,

    --- Decodes the BackendKeyData packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding, -1 on error
    -- @return response table containing zero or more of the following <code>pid</code> and <code>key</code>
    --         error string containing error message if pos is -1
    [MessageType.BackendKeyData] = function( data, len, pos )
      local response = {}

      if len ~= 12 then
        return -1, "ERROR: Invalid BackendKeyData packet"
      end

      pos, response.pid, response.key = bin.unpack(">I>I", data, pos)
      return pos, response
    end,

    --- Decodes an ReadyForQuery packet
    --
    -- @param data string containing raw data received from socket
    -- @param len number containing the length as retrieved from the header
    -- @param pos number containing the offset into the data buffer
    -- @return pos number containing the offset after decoding, -1 on error
    -- @return response table containing zero or more of the following <code>status</code>
    --         error string containing error message if pos is -1
    [MessageType.ReadyForQuery] = function( data, len, pos )
      local response = {}

      if len ~= 5 then
        return -1, "ERROR: Invalid ReadyForQuery packet"
      end

      pos, response.status = bin.unpack("C", data, pos )
      return pos, response
    end,
  },

  --- Reads a packet and handles additional socket reads to retrieve remaining data
  --
  -- @param socket socket already connected to the pgsql server
  -- @param data string containing any data already retrieved from the socket
  -- @param pos number containing the offset into the data buffer
  -- @return data string containing the initial and any additional data
  readPacket = function(socket, data, pos)

    local pos = pos or 1
    local data = data or ""
    local status = true
    local tmp = ""
    local ptype, len
    local header

    local catch = function() socket:close() stdnse.debug1("processResponse(): failed") end
    local try = nmap.new_try(catch)

    if ( data:len() - pos < 5 ) then
      status, tmp = socket:receive_bytes( 5 - ( data:len() - pos ) )
    end

    if not status then
      return nil, "Failed to read packet"
    end

    if tmp:len() ~= 0 then
      data = data .. tmp
    end

    pos, header = v3.decodeHeader(data,pos)

    while data:len() < header.len do
      data = data .. try(socket:receive_bytes( ( header.len + 1 ) - data:len() ))
    end
    return data
  end,

  --- Decodes the postgres header
  --
  -- @param data string containing the server response
  -- @param pos number containing the offset into the data buffer
  -- @return pos number containing the offset after decoding
  -- @return header table containing <code>type</code> and <code>len</code>
  decodeHeader = function(data, pos)
    local ptype, len

    pos, ptype, len = bin.unpack("C>I", data, pos)
    return pos, { ['type'] = ptype, ['len'] = len }
  end,

  --- Process the server response
  --
  -- @param data string containing the server response
  -- @param pos number containing the offset into the data buffer
  -- @return pos number containing offset after decoding
  -- @return response string containing decoded data
  --         error message if pos is -1
  processResponse = function(data, pos)
    local ptype, len, status, response
    local pos = pos or 1
    local header

    pos, header = v3.decodeHeader( data, pos )

    if v3.messageDecoder[header.type] then
      pos, response = v3.messageDecoder[header.type](data, header.len, pos)

      if pos ~= -1 then
        response.type = header.type
        return pos, response
      end
    else
      stdnse.debug1("Missing decoder for %d", header.type )
      return -1, ("Missing decoder for %d"):format(header.type)
    end
    return -1, "Decoding failed"
  end,

  --- Attempts to authenticate to the pgsql server
  -- Supports plain-text and MD5 authentication
  --
  -- @param socket socket already connected to the pgsql server
  -- @param params table containing any additional parameters <code>authtype</code>, <code>version</code>
  -- @param username string containing the username to use for authentication
  -- @param password string containing the password to use for authentication
  -- @param salt string containing the cryptographic salt value
  -- @return status true on success, false on failure
  -- @return result table containing parameter status information,
  --         result string containing an error message if login fails
  loginRequest = function ( socket, params, username, password, salt )

    local catch = function() socket:close() stdnse.debug1("loginRequest(): failed") end
    local try = nmap.new_try(catch)
    local response, header = {}, {}
    local status, data, len, tmp, _
    local pos = 1

    if ( params.authtype == AuthenticationType.MD5 ) then
      local hash = createMD5LoginHash(username, password, salt)
      data = bin.pack( "C>Iz", MessageType.PasswordMessage, 40, hash )
      try( socket:send( data ) )
    elseif ( params.authtype == AuthenticationType.Plain ) then
      local data
      data = bin.pack("C>Iz", MessageType.PasswordMessage, password:len() + 4, password)
      try( socket:send( data ) )
    elseif ( params.authtype == AuthenticationType.Success ) then
      return true, nil
    end

    data, response.params = "", {}

    data = v3.readPacket(socket, data, 1)
    pos, tmp = v3.processResponse(data, 1)

    -- this should contain the AuthRequest packet
    if tmp.type ~= MessageType.AuthRequest then
      return false, "Expected AuthRequest got something else"
    end

    if not tmp.success then
      return false, "Login failure"
    end

    repeat
      data = v3.readPacket(socket, data, pos)
      pos, tmp = v3.processResponse(data, pos)
      if ( tmp.type == MessageType.ParameterStatus ) then
        table.insert(response.params, {name=tmp.key, value=tmp.value})
      end
    until pos >= data:len() or pos == -1

    return true, response
  end,

  --- Sends a startup message to the server containing the username and database to connect to
  --
  -- @param socket socket already connected to the pgsql server
  -- @param user string containing the name of the user
  -- @param database string containing the name of the database
  -- @return status true on success, false on failure
  -- @return table containing a processed response from <code>processResponse</code>
  --         string containing error message if status is false
  sendStartup = function(socket, user, database )
    local data, response, status, pos
    local proto_ver, ptype, _, tmp

    proto_ver = 0x0030000
    data = bin.pack(">IzzzzH", proto_ver, "user", user, "database", database, 0)
    data = bin.pack(">I", data:len() + 4) .. data

    socket:send( data )

    -- attempt to verify version
    status, data = socket:receive_bytes( 2 )

    if ( not(status) ) then
      return false, "sendStartup failed"
    end

    if ( not(status) or data:match("^EF") ) then
      return false, "Incorrect version"
    end

    data = v3.readPacket(socket, data )
    pos, response = v3.processResponse( data )

    if ( pos < 0 or response.type == MessageType.Error) then
      return false, response.error.message or "unknown error"
    end

    return true, response
  end
}


--- Sends a packet requesting SSL communication to be activated
--
-- @param socket socket already connected to the pgsql server
-- @return boolean true if request was accepted, false if request was denied
function requestSSL(socket)
  -- SSLRequest
  local ssl_req_code = 80877103
  local data = bin.pack( ">I>I", 8, ssl_req_code)
  local status, response

  socket:send(data)
  status, response = socket:receive_bytes(1)

  if ( not(status) ) then
    return false
  end

  if ( response == 'S' ) then
    return true
  end

  return false
end

--- Creates a cryptographic hash to be used for login
--
-- @param username username
-- @param password password
-- @param salt salt
-- @return string suitable for login request
function createMD5LoginHash(username, password, salt)
  local md5_1 = select( 2, bin.unpack( "H16", openssl.md5(password..username) ) ):lower()
  return "md5" .. select( 2, bin.unpack("H16", openssl.md5(  md5_1 .. salt  ) ) ):lower()
end

--- Prints the contents of the error table returned from the Error message decoder
--
-- @param dberror table containing the error
function printErrorMessage( dberror )
  if not dberror then
    return
  end
  for k, v in pairs(dberror) do
    stdnse.debug1("%s=%s", k, v)
  end
end

--- Attempts to determine if the server supports v3 or v2 of the protocol
--
-- @param host table
-- @param port table
-- @return class v2 or v3
function detectVersion(host, port)
  local status, response
  local socket = nmap.new_socket()

  socket:connect(host, port)
  status, response = v3.sendStartup(socket, "versionprobe", "versionprobe")
  socket:close()

  if ( not(status) and response == 'Incorrect version' ) then
    return v2
  end

  return v3
end

return _ENV;
