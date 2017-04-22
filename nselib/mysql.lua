---
-- Simple MySQL Library supporting a very limited subset of operations.
--
-- https://dev.mysql.com/doc/internals/en/client-server-protocol.html
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @author Patrik Karlsson <patrik@cqure.net>

local bin = require "bin"
local bit = require "bit"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
_ENV = stdnse.module("mysql", stdnse.seeall)

-- Version 0.3
--
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/23/2010 - v0.2 - added query support, cleanup, documentation
-- Revised 08/24/2010 - v0.3 - added error handling for receiveGreeting
--                             fixed a number of incorrect receives and changed
--                             them to receive_bytes instead.

local tab = require('tab')

local HAVE_SSL, openssl = pcall(require,'openssl')

Capabilities =
{
  LongPassword = 0x1,
  FoundRows = 0x2,
  LongColumnFlag = 0x4,
  ConnectWithDatabase = 0x8,
  DontAllowDatabaseTableColumn = 0x10,
  SupportsCompression = 0x20,
  ODBCClient = 0x40,
  SupportsLoadDataLocal = 0x80,
  IgnoreSpaceBeforeParenthesis = 0x100,
  Speaks41ProtocolNew = 0x200,
  InteractiveClient = 0x400,
  SwitchToSSLAfterHandshake = 0x800,
  IgnoreSigpipes = 0x1000,
  SupportsTransactions = 0x2000,
  Speaks41ProtocolOld = 0x4000,
  Support41Auth = 0x8000
}

ExtCapabilities =
{
  SupportsMultipleStatments = 0x1,
  SupportsMultipleResults = 0x2,
  SupportsAuthPlugins = 0x8,
}

Charset =
{
  latin1_COLLATE_latin1_swedish_ci = 0x8
}

ServerStatus =
{
  InTransaction = 0x1,
  AutoCommit = 0x2,
  MoreResults = 0x4,
  MultiQuery = 0x8,
  BadIndexUsed = 0x10,
  NoIndexUsed = 0x20,
  CursorExists = 0x40,
  LastRowSebd = 0x80,
  DatabaseDropped = 0x100,
  NoBackslashEscapes = 0x200
}

Command =
{
  Query = 3
}

local MAXPACKET = 16777216
local HEADER_SIZE = 4


--- Parses a MySQL header
--
-- @param data string of raw data
-- @return response table containing the fields <code>len</code> and <code>packetno</code>
local function decodeHeader( data, pos )

  local response = {}
  local pos, tmp = pos or 1, 0

  pos, tmp = bin.unpack( "I", data, pos )
  response.len = bit.band( tmp,255 )
  response.number = bit.rshift( tmp, 24 )

  return pos, response
end

--- Receives the server greeting upon initial connection
--
-- @param socket already connected to the remote server
-- @return status true on success, false on failure
-- @return response table with the following fields <code>proto</code>, <code>version</code>,
-- <code>threadid</code>, <code>salt</code>, <code>capabilities</code>, <code>charset</code> and
-- <code>status</code> or error message on failure (status == false)
function receiveGreeting( socket )

  local catch = function() socket:close() stdnse.debug1("receiveGreeting(): failed") end
  local try = nmap.new_try(catch)
  local data = try( socket:receive_bytes(HEADER_SIZE) )
  local pos, response, tmp, _

  pos, response = decodeHeader( data, 1 )

  -- do we need to read the remainder
  if ( #data - HEADER_SIZE < response.len ) then
    local tmp = try( socket:receive_bytes( response.len - #data + HEADER_SIZE ) )
    data = data .. tmp
  end

  local is_error
  pos, is_error = bin.unpack( "C", data, pos )

  if ( is_error == 0xff ) then
    pos, response.errorcode = bin.unpack( "<S", data, pos )
    pos, response.errormsg = bin.unpack("A" .. (#data - pos + 1), data, pos )

    return false, response.errormsg
  end

  response.proto = is_error
  pos, response.version = bin.unpack( "z", data, pos )
  pos, response.threadid = bin.unpack( "<I", data, pos )

  if response.proto == 10 then
    pos, response.salt, _ = bin.unpack( "A8C", data, pos )
    pos, response.capabilities = bin.unpack( "<S", data, pos )
    if pos < #data then
      pos, response.charset = bin.unpack( "C", data, pos )
      pos, response.status = bin.unpack( "<S", data, pos )
      pos, response.extcapabilities = bin.unpack( "<S", data, pos) -- capabilities, upper 2 bytes
      local auth_plugin_len
      pos, auth_plugin_len = bin.unpack("C", data, pos)
      pos, tmp = bin.unpack( "A10", data, pos )
      if tmp ~= "\0\0\0\0\0\0\0\0\0\0" then
        stdnse.debug2("reserved bytes are not nulls")
      end
      if response.capabilities & Capabilities.Support41Auth > 0 then
        pos, tmp, _ = bin.unpack("A" .. (math.max(13, auth_plugin_len - 8) - 1) .. "x", data, pos)
        response.salt = response.salt .. tmp
      end
      if response.extcapabilities & ExtCapabilities.SupportsAuthPlugins > 0 then
        response.auth_plugin_name = bin.unpack("z", data, pos)
      end
    end
  elseif response.proto == 9 then
    pos, response.auth_plugin_data = bin.unpack( "z", data, pos )
  else
    stdnse.debug2("Unknown MySQL protocol version: %d", response.proto)
  end

  response.errorcode = 0

  return true, response

end


--- Creates a hashed value of the password and salt according to MySQL authentication post version 4.1
--
-- @param pass string containing the users password
-- @param salt string containing the servers salt as obtained from <code>receiveGreeting</code>
-- @return reply string containing the raw hashed value
local function createLoginHash(pass, salt)
  local hash_stage1
  local hash_stage2
  local hash_stage3
  local reply = {}
  local pos, b1, b2, b3, _ = 1, 0, 0, 0

  if ( not(HAVE_SSL) ) then
    return nil
  end

  hash_stage1 = openssl.sha1( pass )
  hash_stage2 = openssl.sha1( hash_stage1 )
  hash_stage3 = openssl.sha1( salt .. hash_stage2 )

  for pos=1, hash_stage1:len() do
    _, b1 = bin.unpack( "C", hash_stage1, pos )
    _, b2 = bin.unpack( "C", hash_stage3, pos )

    reply[pos] = string.char( bit.bxor( b2, b1 ) )
  end

  return table.concat(reply)

end


--- Attempts to Login to the remote mysql server
--
-- @param socket already connected to the remote server
-- @param params table with additional options to the loginrequest
--               current supported fields are <code>charset</code> and <code>authversion</code>
--               authversion is either "pre41" or "post41" (default is post41)
--               currently only post41 authentication is supported
-- @param username string containing the username of the user that is authenticating
-- @param password string containing the users password or nil if empty
-- @param salt string containing the servers salt as received from <code>receiveGreeting</code>
-- @return status boolean
-- @return response table or error message on failure
function loginRequest( socket, params, username, password, salt )

  local catch = function() socket:close() stdnse.debug1("loginRequest(): failed") end
  local try = nmap.new_try(catch)
  local packetno = 1
  local authversion = params.authversion or "post41"
  local username = username or ""

  if not(HAVE_SSL) then
    return false, "No OpenSSL"
  end

  if authversion ~= "post41" then
    return false, "Unsupported authentication version: " .. authversion
  end

  local clicap = Capabilities.LongPassword
  clicap = clicap + Capabilities.LongColumnFlag
  clicap = clicap + Capabilities.SupportsLoadDataLocal
  clicap = clicap + Capabilities.Speaks41ProtocolNew
  clicap = clicap + Capabilities.InteractiveClient
  clicap = clicap + Capabilities.SupportsTransactions
  clicap = clicap + Capabilities.Support41Auth

  local extcapabilities = ExtCapabilities.SupportsMultipleStatments
  extcapabilities = extcapabilities + ExtCapabilities.SupportsMultipleResults

  local hash = ""
  if ( password ~= nil and password:len() > 0 ) then
    hash = createLoginHash( password, salt )
  end

  local packet = bin.pack( "SSICAzp",
    clicap,
    extcapabilities,
    MAXPACKET,
    Charset.latin1_COLLATE_latin1_swedish_ci,
    string.rep("\0", 23),
    username,
    hash
    )

  local tmp = packet:len() + bit.lshift( packetno, 24 )

  packet = bin.pack( "I", tmp ) .. packet

  try( socket:send(packet) )
  packet = try( socket:receive_bytes(HEADER_SIZE) )
  local pos, response = decodeHeader( packet )

  -- do we need to read the remainder
  if ( #packet - HEADER_SIZE < response.len ) then
    local tmp = try( socket:receive_bytes( response.len - #packet + HEADER_SIZE ) )
    packet = packet .. tmp
  end

  local is_error

  pos, is_error = bin.unpack( "C", packet, pos )

  if is_error > 0 then
    pos, response.errorcode = bin.unpack( "S", packet, pos )

    local has_sqlstate
    pos, has_sqlstate = bin.unpack( "C", packet, pos )

    if has_sqlstate == 35 then
      pos, response.sqlstate = bin.unpack( "A5", packet, pos )
    end

    pos, response.errormessage = bin.unpack( "z", packet, pos )

    return false, response.errormessage
  else
    response.errorcode = 0
    pos, response.affectedrows = bin.unpack( "C", packet, pos )
    pos, response.serverstatus = bin.unpack( "S", packet, pos )
    pos, response.warnings = bin.unpack( "S", packet, pos )
  end

  return true, response

end

--- Decodes a single column field
--
-- http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Field_Packet
--
-- @param data string containing field packets
-- @param pos number containing position from which to start decoding
--            the position should point to the data in this buffer (ie. after the header)
-- @return pos number containing the position after the field was decoded
-- @return field table containing <code>catalog</code>, <code>database</code>, <code>table</code>,
--         <code>origt_table</code>, <code>name</code>, <code>orig_name</code>,
--         <code>length</code> and <code>type</code>
function decodeField( data, pos )

  local header, len
  local def, _
  local field = {}

  pos, len = bin.unpack( "C", data, pos )
  pos, field.catalog = bin.unpack( "A" .. len, data, pos )

  pos, len = bin.unpack( "C", data, pos )
  pos, field.database = bin.unpack( "A" .. len, data, pos )

  pos, len = bin.unpack( "C", data, pos )
  pos, field.table = bin.unpack( "A" .. len, data, pos )

  pos, len = bin.unpack( "C", data, pos )
  pos, field.orig_table = bin.unpack( "A" .. len, data, pos )

  pos, len = bin.unpack( "C", data, pos )
  pos, field.name = bin.unpack( "A" .. len, data, pos )

  pos, len = bin.unpack( "C", data, pos )
  pos, field.orig_name = bin.unpack( "A" .. len, data, pos )

  -- should be 0x0C
  pos, _ = bin.unpack( "C", data, pos )

  -- charset, in my case 0x0800
  pos, _ = bin.unpack( "S", data, pos )

  pos, field.length = bin.unpack( "I", data, pos )
  pos, field.type = bin.unpack( "A6", data, pos )

  return pos, field

end

--- Decodes the result set header packet into its sub components
--
-- ref: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Result_Set_Header_Packet
--
-- @param socket socket already connected to MySQL server
-- @return table containing the following <code>header</code>, <code>fields</code> and <code>data</code>
function decodeQueryResponse( socket )

  local catch = function() socket:close() stdnse.debug1("decodeQueryResponse(): failed") end
  local try = nmap.new_try(catch)
  local data, header, pos
  local rs, blocks = {}, {}
  local block_start, block_end
  local EOF_MARKER = 254

  data = try( socket:receive_bytes(HEADER_SIZE) )
  pos, header = decodeHeader( data, pos )

  --
  -- First, Let's attempt to read the "Result Set Header Packet"
  --
  if data:len() < header.len then
    data = data .. try( socket:receive_bytes( header.len - #data + HEADER_SIZE ) )
  end

  rs.header = data:sub( 1, HEADER_SIZE + header.len )

  -- abort on MySQL error
  if rs.header:sub(HEADER_SIZE + 1, HEADER_SIZE + 1) == "\xFF" then
    -- is this a 4.0 or 4.1 error message
    if rs.header:find("#") then
      return false, rs.header:sub(HEADER_SIZE+10)
    else
      return false, rs.header:sub(HEADER_SIZE+4)
    end
  end

  pos = HEADER_SIZE + header.len + 1

  -- Second, Let's attempt to read the "Field Packets" and "Row Data Packets"
  -- They're separated by an "EOF Packet"
  for i=1,2 do

    -- marks the start of our block
    block_start = pos

    while true do

      if data:len() - pos < HEADER_SIZE then
        data = data .. try( socket:receive_bytes( HEADER_SIZE - ( data:len() - pos ) ) )
      end

      pos, header = decodeHeader( data, pos )

      if data:len() - pos < header.len - 1 then
        data = data .. try( socket:receive_bytes( header.len - ( data:len() - pos ) ) )
      end

      if header.len > 0 then
        local _, b = bin.unpack("C", data, pos )

        -- Is this the EOF packet?
        if b == EOF_MARKER then
          -- we don't want the EOF Packet included
          block_end = pos - HEADER_SIZE
          pos = pos + header.len
          break
        end
      end

      pos = pos + header.len

    end

    blocks[i] = data:sub( block_start, block_end )

  end


  rs.fields = blocks[1]
  rs.data = blocks[2]

  return true, rs

end

--- Decodes as field packet and returns a table of field tables
--
-- ref: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Field_Packet
--
-- @param data string containing field packets
-- @param count number containing the amount of fields to decode
-- @return status boolean (true on success, false on failure)
-- @return fields table containing field tables as returned by <code>decodeField</code>
--         or string containing error message if status is false
function decodeFieldPackets( data, count )

  local pos, header
  local field, fields = {}, {}

  if count < 1 then
    return false, "Field count was less than one, aborting"
  end

  for i=1, count do
    pos, header = decodeHeader( data, pos )
    pos, field = decodeField( data, pos )
    table.insert( fields, field )
  end

  return true, fields
end

-- Decodes the result set header
--
-- ref: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Result_Set_Header_Packet
--
-- @param data string containing the result set header packet
-- @return number containing the amount of fields
function decodeResultSetHeader( data )

  local _, fields

  if data:len() ~= HEADER_SIZE + 1 then
    return false, "Result set header was incorrect"
  end

  _, fields = bin.unpack( "C", data, HEADER_SIZE + 1 )

  return true, fields
end

--- Decodes the row data
--
-- ref: http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Row_Data_Packet
--
-- @param data string containing the row data packet
-- @param count number containing the number of fields to decode
-- @return status true on success, false on failure
-- @return rows table containing row tables
function decodeDataPackets( data, count )

  local len, pos = 0, 1, 1
  local header, row, rows = {}, {}, {}

  while pos < data:len() do
    row = {}
    pos, header = decodeHeader( data, pos )

    for i=1, count do
      pos, len = bin.unpack("C", data, pos )
      pos, row[i] = bin.unpack("A" .. len, data, pos)
    end

    table.insert( rows, row )

  end

  return true, rows

end

--- Sends the query to the MySQL server and then attempts to decode the response
--
-- @param socket socket already connected to mysql
-- @param query string containing the sql query
-- @return status true on success, false on failure
-- @return rows table containing row tables as decoded by <code>decodeDataPackets</code>
function sqlQuery( socket, query )

  local catch = function() socket:close() stdnse.debug1("sqlQuery(): failed") end
  local try = nmap.new_try(catch)
  local packetno = 0
  local querylen = query:len() + 1
  local packet, packet_len, pos, header
  local status, fields, field_count, rows, rs

  packet = bin.pack("<ICA", querylen, Command.Query, query )

  --
  -- http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol#Result_Set_Header_Packet
  --
  -- (Result Set Header Packet)  the number of columns
  -- (Field Packets)             column descriptors
  -- (EOF Packet)                marker: end of Field Packets
  -- (Row Data Packets)          row contents
  -- (EOF Packet)                marker: end of Data Packets

  try( socket:send(packet) )

  --
  -- Let's read all the data into a table
  -- This way we avoid the hustle with reading from the socket
  status, rs = decodeQueryResponse( socket )

  if not status then
    return false, rs
  end

  status, field_count = decodeResultSetHeader(rs.header)

  if not status then
    return false, field_count
  end

  status, fields = decodeFieldPackets(rs.fields, field_count)

  if not status then
    return false, fields
  end

  status, rows = decodeDataPackets(rs.data, field_count)

  if not status then
    return false, rows
  end

  return true, { cols = fields, rows = rows }
end

---
-- Formats the resultset returned from <code>sqlQuery</code>
--
-- @param rs table as returned from <code>sqlQuery</code>
-- @param options table containing additional options, currently:
--        - <code>noheaders</code> - does not include column names in result
-- @return string containing the formatted resultset table
function formatResultset(rs, options)
  options = options or {}
  if ( not(rs) or not(rs.cols) or not(rs.rows) ) then
    return
  end

  local restab = tab.new(#rs.cols)
  local colnames = {}

  if ( not(options.noheaders) ) then
    for _, col in ipairs(rs.cols) do table.insert(colnames, col.name) end
    tab.addrow(restab, table.unpack(colnames))
  end

  for _, row in ipairs(rs.rows) do
    tab.addrow(restab, table.unpack(row))
  end

  return tab.dump(restab)
end

return _ENV;
