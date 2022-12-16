---
-- Library methods for handling LDAP.
--
-- @author Patrik Karlsson
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Credit goes out to Martin Swende who provided me with the initial code that got me started writing this.
--
-- Version 0.8
-- Created 01/12/2010 - v0.1 - Created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/28/2010 - v0.2 - Revised to fit better fit ASN.1 library
-- Revised 02/02/2010 - v0.3 - Revised to fit OO ASN.1 Library
-- Revised 09/05/2011 - v0.4 - Revised to include support for writing output to file, added decoding certain time
--                             formats
-- Revised 10/29/2011 - v0.5 - Added support for performing wildcard searches via the substring filter.
-- Revised 10/30/2011 - v0.6 - Added support for the ldap extensibleMatch filter type for searches
-- Revised 04/04/2016 - v0.7 - Added support for searchRequest over upd ( udpSearchRequest ) - Tom Sellers
-- Revised 07/11/2017 - v0.8 - Added support for decoding the objectSID Active Directory attribute - Tom Sellers
--

local asn1 = require "asn1"
local datetime = require "datetime"
local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local comm = require "comm"
_ENV = stdnse.module("ldap", stdnse.seeall)

local ldapMessageId = 1

ERROR_MSG = {}
ERROR_MSG[1]  = "Initialization of LDAP library failed."
ERROR_MSG[4]  = "Size limit exceeded."
ERROR_MSG[13] = "Confidentiality required"
ERROR_MSG[32] = "No such object"
ERROR_MSG[34] = "Invalid DN"
ERROR_MSG[49] = "The supplied credential is invalid."

ERRORS = {
  LDAP_SUCCESS = 0,
  LDAP_SIZELIMIT_EXCEEDED = 4
}

--- Application constants
-- @class table
-- @name APPNO
APPNO = {
  BindRequest = 0,
  BindResponse = 1,
  UnbindRequest = 2,
  SearchRequest = 3,
  SearchResponse = 4,
  SearchResDone = 5
}

-- Filter operation constants
FILTER = {
  _and = 0,
  _or = 1,
  _not = 2,
  equalityMatch = 3,
  substrings = 4,
  greaterOrEqual = 5,
  lessOrEqual = 6,
  present = 7,
  approxMatch = 8,
  extensibleMatch = 9
}

-- Scope constants
SCOPE = {
  base=0,
  one=1,
  sub= 2,
  children=3,
  default = 0
}

-- Deref policy constants
DEREFPOLICY = {
  never=0,
  searching=1,
  finding = 2,
  always=3,
  default = 0
}

-- LDAP specific tag encoders
local tagEncoder = {}

tagEncoder['table'] = function(self, val)
  if (val._ldap == '\x0A') then
    local ival = self.encodeInt(val[1])
    local len = self.encodeLength(#ival)
    return val._ldap .. len .. ival
  end
  if (val._ldaptype) then
    local len
    if val[1] == nil or #val[1] == 0 then
      return val._ldaptype .. '\0'
    else
      len = self.encodeLength(#val[1])
      return val._ldaptype .. len .. val[1]
    end
  end

  local encVal = ""
  for _, v in ipairs(val) do
    encVal = encVal .. encode(v) -- todo: buffer?
  end
  local tableType = val._snmp or "\x30"
  return tableType .. self.encodeLength(#encVal) .. encVal

end

---
-- Encodes a given value according to ASN.1 basic encoding rules for SNMP
-- packet creation.
-- @param val Value to be encoded.
-- @return Encoded value.
function encode(val)

  local encoder = asn1.ASN1Encoder:new()
  local encValue

  encoder:registerTagEncoders(tagEncoder)
  encValue = encoder:encode(val)

  if encValue then
    return encValue
  end

  return ''
end


-- LDAP specific tag decoders
local tagDecoder = {}

tagDecoder["\x0A"] = function( self, encStr, elen, pos )
  return self.decodeInt(encStr, elen, pos)
end

tagDecoder["\x8A"] = function( self, encStr, elen, pos )
  return string.unpack("c" .. elen, encStr, pos)
end

-- null decoder
tagDecoder["\x31"] = function( self, encStr, elen, pos )
  return nil, pos
end


---
-- Decodes an LDAP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The decoded value(s).
-- @return The position after decoding
function decode(encStr, pos)
  -- register the LDAP specific tag decoders
  local decoder = asn1.ASN1Decoder:new()
  decoder:registerTagDecoders( tagDecoder )
  return decoder:decode( encStr, pos )
end


---
-- Decodes a sequence according to ASN.1 basic encoding rules.
-- @param encStr Encoded string.
-- @param len Length of sequence in bytes.
-- @param pos Current position in the string.
-- @return The decoded sequence as a table.
-- @return The position after decoding.
local function decodeSeq(encStr, len, pos)
  local seq = {}
  local sPos = 1
  if #encStr - pos + 1 < len then
    return seq, nil
  end
  local sStr, newpos = string.unpack("c" .. len, encStr, pos)
  while (sPos < len) do
    local newSeq
    newSeq, sPos = decode(sStr, sPos)
    table.insert(seq, newSeq)
  end
  return seq, newpos
end

-- Encodes an LDAP Application operation and its data as a sequence
--
-- @param appno LDAP application number
-- @see APPNO
-- @param isConstructed boolean true if constructed, false if primitive
-- @param data string containing the LDAP operation content
-- @return string containing the encoded LDAP operation
function encodeLDAPOp( appno, isConstructed, data )
  local encoded_str = ""
  local asn1_type = asn1.BERtoInt( asn1.BERCLASS.Application, isConstructed, appno )

  encoded_str = encode( { _ldaptype = string.pack("B", asn1_type), data } )
  return encoded_str
end

--- Performs an LDAP Search request
--
-- This function has a concept of softerrors which populates the return tables error information
-- while returning a true status. The reason for this is that LDAP may return a number of records
-- and then finish off with an error like SIZE LIMIT EXCEEDED. We still want to return the records
-- that were received prior to the error. In order to achieve this and not terminating the script
-- by returning a false status a true status is returned together with a table containing all searchentries.
-- This table has the <code>errorMessage</code> and <code>resultCode</code> entries set with the error information.
-- As a <code>try</code> won't catch this error it's up to the script to do so. See ldap-search.nse for an example.
--
-- @param socket socket already connected to the ldap server
-- @param params table containing at least <code>scope</code>, <code>derefPolicy</code>, <code>baseObject</code>
--        the field <code>maxObjects</code> may also be included to restrict the amount of records returned
-- @return success true or false.
-- @return searchResEntries containing results or a string containing error message
function searchRequest( socket, params )

  local searchResEntries = { errorMessage="", resultCode = 0}
  local catch = function() socket:close() stdnse.debug1("SearchRequest failed") end
  local try = nmap.new_try(catch)
  local attributes = params.attributes
  local request = encode(params.baseObject)
  local attrSeq = ''
  local requestData, messageSeq, data
  local maxObjects = params.maxObjects or -1

  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  request = request .. encode( { _ldap='\x0A', params.scope } )--scope
  request = request .. encode( { _ldap='\x0A', params.derefPolicy } )--derefpolicy
  request = request .. encode( params.sizeLimit or 0)--sizelimit
  request = request .. encode( params.timeLimit or 0)--timelimit
  request = request .. encode( params.typesOnly or false)--TypesOnly

  if params.filter then
    request = request .. createFilter( params.filter )
  else
    request = request .. encode( { _ldaptype='\x87', "objectclass" } )-- filter : string, presence
  end
  if  attributes~= nil then
    for _,attr in ipairs(attributes) do
      attrSeq = attrSeq .. encode(attr)
    end
  end

  request = request .. encoder:encodeSeq(attrSeq)
  requestData = encodeLDAPOp(APPNO.SearchRequest, true, request)
  messageSeq = encode(ldapMessageId)
  ldapMessageId = ldapMessageId +1
  messageSeq = messageSeq .. requestData
  data = encoder:encodeSeq(messageSeq)
  try( socket:send( data ) )
  data = ""

  while true do
    local len, pos, messageId = 0, 2, -1
    local tmp = ""
    local _, objectName, attributes, ldapOp
    local attributes
    local searchResEntry = {}

    if ( maxObjects == 0 ) then
      break
    elseif ( maxObjects > 0 ) then
      maxObjects = maxObjects - 1
    end

    if data:len() > 6 then
      len, pos = decoder.decodeLength( data, pos )
    else
      data = data .. try( socket:receive() )
      len, pos = decoder.decodeLength( data, pos )
    end
    -- pos should be at the right position regardless if length is specified in 1 or 2 bytes
    while ( len + pos - 1 > data:len() ) do
      data = data .. try( socket:receive() )
    end

    messageId, pos = decode( data, pos )
    tmp, pos = string.unpack("B", data, pos)
    len, pos = decoder.decodeLength( data, pos )
    ldapOp = asn1.intToBER( tmp )
    searchResEntry = {}

    if ldapOp.number == APPNO.SearchResDone then
      searchResEntry.resultCode, pos = decode( data, pos )
      -- errors may occur after a large amount of data has been received (eg. size limit exceeded)
      -- we want to be able to return the data received prior to this error to the user
      -- however, we also need to alert the user of the error. This is achieved through "softerrors"
      -- softerrors populate the error fields of the table while returning a true status
      -- this allows for the caller to output data while still being able to catch the error
      if ( searchResEntry.resultCode ~= 0 ) then
        local error_msg
        searchResEntry.matchedDN, pos = decode( data, pos )
        searchResEntry.errorMessage, pos = decode( data, pos )
        error_msg = ERROR_MSG[searchResEntry.resultCode]
        -- if the table is empty return a hard error
        if #searchResEntries == 0 then
          return false, string.format("Code: %d|Error: %s|Details: %s", searchResEntry.resultCode, error_msg or "", searchResEntry.errorMessage or "" )
        else
          searchResEntries.errorMessage = string.format("Code: %d|Error: %s|Details: %s", searchResEntry.resultCode, error_msg or "", searchResEntry.errorMessage or "" )
          searchResEntries.resultCode = searchResEntry.resultCode
          return true, searchResEntries
        end
      end
      break
    end

    searchResEntry.objectName, pos = decode( data, pos )
    if ldapOp.number == APPNO.SearchResponse then
      searchResEntry.attributes, pos = decode( data, pos )

      table.insert( searchResEntries, searchResEntry )
    end
    if data:len() > pos then
      data = data:sub(pos)
    else
      data = ""
    end
  end
  return true, searchResEntries
end

--- Performs an LDAP Search request over UDP
--
-- This function has a concept of softerrors which populates the return tables error information
-- while returning a true status. The reason for this is that LDAP may return a number of records
-- and then finish off with an error like SIZE LIMIT EXCEEDED. We still want to return the records
-- that were received prior to the error. In order to achieve this and not terminating the script
-- by returning a false status a true status is returned together with a table containing all searchentries.
-- This table has the <code>errorMessage</code> and <code>resultCode</code> entries set with the error information.
-- As a <code>try</code> won't catch this error it's up to the script to do so. See ldap-search.nse for an example.
--
-- @param host The host to connect to
-- @param port The port on the host
-- @param params table containing at least <code>scope</code>, <code>derefPolicy</code>, <code>baseObject</code>
--        the field <code>maxObjects</code> may also be included to restrict the amount of records returned
-- @return success true or false.
-- @return searchResEntries containing results or a string containing error message

function udpSearchRequest( host, port, params )

  local searchResEntries = { errorMessage="", resultCode = 0}
  local catch = function() stdnse.debug1("udpSearchRequest failed") end
  local try = nmap.new_try(catch)
  local attributes = params.attributes
  local request = encode(params.baseObject)
  local attrSeq = ''
  local requestData, messageSeq, data
  local maxObjects = params.maxObjects or -1

  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  request = request .. encode( { _ldap='\x0A', params.scope } )--scope
  request = request .. encode( { _ldap='\x0A', params.derefPolicy } )--derefpolicy
  request = request .. encode( params.sizeLimit or 0)--sizelimit
  request = request .. encode( params.timeLimit or 0)--timelimit
  request = request .. encode( params.typesOnly or false)--TypesOnly

  if params.filter then
    request = request .. createFilter( params.filter )
  else
    request = request .. encode( { _ldaptype='\x87', "objectclass" } )-- filter : string, presence
  end
  if  attributes~= nil then
    for _,attr in ipairs(attributes) do
      attrSeq = attrSeq .. encode(attr)
    end
  end

  request = request .. encoder:encodeSeq(attrSeq)
  requestData = encodeLDAPOp(APPNO.SearchRequest, true, request)
  messageSeq = encode(ldapMessageId)
  ldapMessageId = ldapMessageId +1
  messageSeq = messageSeq .. requestData
  data = encoder:encodeSeq(messageSeq)
  local status, response = comm.exchange(host, port, data)

  while true do
    local len, pos, messageId = 0, 0, -1
    local tmp = ""
    local _, objectName, attributes, ldapOp
    local attributes
    local searchResEntry = {}

    if ( maxObjects == 0 ) then
      break
    elseif ( maxObjects > 0 ) then
      maxObjects = maxObjects - 1
    end

    tmp, pos = string.unpack("B", response, pos)
    len, pos = decoder.decodeLength( response, pos )
    messageId, pos = decode( response, pos )
    tmp, pos = string.unpack("B", response, pos)
    len, pos = decoder.decodeLength( response, pos )
    ldapOp = asn1.intToBER( tmp )
    searchResEntry = {}

    if ldapOp.number == APPNO.SearchResDone then
      searchResEntry.resultCode, pos = decode( response, pos )
      -- errors may occur after a large amount of response has been received (eg. size limit exceeded)
      -- we want to be able to return the response received prior to this error to the user
      -- however, we also need to alert the user of the error. This is achieved through "softerrors"
      -- softerrors populate the error fields of the table while returning a true status
      -- this allows for the caller to output response while still being able to catch the error
      if ( searchResEntry.resultCode ~= 0 ) then
        local error_msg
        searchResEntry.matchedDN, pos = decode( response, pos )
        searchResEntry.errorMessage, pos = decode( response, pos )
        error_msg = ERROR_MSG[searchResEntry.resultCode]
        -- if the table is empty return a hard error
        if #searchResEntries == 0 then
          return false, string.format("Code: %d|Error: %s|Details: %s", searchResEntry.resultCode, error_msg or "", searchResEntry.errorMessage or "" )
        else
          searchResEntries.errorMessage = string.format("Code: %d|Error: %s|Details: %s", searchResEntry.resultCode, error_msg or "", searchResEntry.errorMessage or "" )
          searchResEntries.resultCode = searchResEntry.resultCode
          return true, searchResEntries
        end
      end
      break
    end

    searchResEntry.objectName, pos = decode( response, pos )
    if ldapOp.number == APPNO.SearchResponse then
      searchResEntry.attributes, pos = decode( response, pos )
      table.insert( searchResEntries, searchResEntry )
    end
    if response:len() > pos then
      response = response:sub(pos)
    else
      response = ""
    end
  end
  return true, searchResEntries
end

--- Attempts to bind to the server using the credentials given
--
-- @param socket socket already connected to the ldap server
-- @param params table containing <code>version</code>, <code>username</code> and <code>password</code>
-- @return success true or false
-- @return err string containing error message
function bindRequest( socket, params )

  local catch = function() socket:close() stdnse.debug1("bindRequest failed") end
  local try = nmap.new_try(catch)
  local ldapAuth = encode( { _ldaptype = '\x80', params.password } )
  local bindReq = encode( params.version ) .. encode( params.username ) .. ldapAuth
  local ldapMsg = encode(ldapMessageId) .. encodeLDAPOp( APPNO.BindRequest, true, bindReq )
  local packet
  local pos, packet_len, resultCode, tmp, len, _
  local response = {}

  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  packet = encoder:encodeSeq( ldapMsg )
  ldapMessageId = ldapMessageId +1
  try( socket:send( packet ) )
  packet = try( socket:receive() )

  packet_len, pos = decoder.decodeLength( packet, 2 )
  response.messageID, pos = decode( packet, pos )
  tmp, pos = string.unpack("B", packet, pos)
  len, pos = decoder.decodeLength( packet, pos )
  response.protocolOp = asn1.intToBER( tmp )

  if response.protocolOp.number ~= APPNO.BindResponse then
    return false, string.format("Received incorrect Op in packet: %d, expected %d", response.protocolOp.number, APPNO.BindResponse)
  end

  response.resultCode, pos = decode( packet, pos )

  if ( response.resultCode ~= 0 ) then
    local error_msg
    response.matchedDN, pos = decode( packet, pos )
    response.errorMessage, pos = decode( packet, pos )
    error_msg = ERROR_MSG[response.resultCode]
    return false, string.format("\n  Error: %s\n  Details: %s",
      error_msg or "Unknown error occurred (code: " .. response.resultCode ..
      ")", response.errorMessage or "" )
  else
    return true, "Success"
  end
end

--- Performs an LDAP Unbind
--
-- @param socket socket already connected to the ldap server
-- @return success true or false
-- @return err string containing error message
function unbindRequest( socket )

  local ldapMsg, packet
  local catch = function() socket:close() stdnse.debug1("bindRequest failed") end
  local try = nmap.new_try(catch)

  local encoder = asn1.ASN1Encoder:new()
  encoder:registerTagEncoders(tagEncoder)

  ldapMessageId = ldapMessageId +1
  ldapMsg = encode( ldapMessageId ) .. encodeLDAPOp( APPNO.UnbindRequest, false, nil)
  packet = encoder:encodeSeq( ldapMsg )
  try( socket:send( packet ) )
  return true, ""
end


--- Creates an ASN1 structure from a filter table
--
-- @param filter table containing the filter to be created
-- @return string containing the ASN1 byte sequence
function createFilter( filter )

  local asn1_type = asn1.BERtoInt( asn1.BERCLASS.ContextSpecific, true, filter.op )
  local filter_str = ""

  if type(filter.val) == 'table' then
    for _, v in ipairs( filter.val ) do
      filter_str = filter_str .. createFilter( v )
    end
  else
    local obj = encode( filter.obj )
    local val = ''
    if ( filter.op == FILTER['substrings'] ) then

      local tmptable = stringaux.strsplit('*', filter.val)
      local tmp_result = ''

      if (#tmptable <= 1 ) then
        -- 0x81  = 10000001  =  10        0                 00001
        -- hex     binary       Context   Primitive value   Field: Sequence  Value: 1 (any / any position in string)
        tmp_result = string.pack('Bs1', 0x81, filter.val)
      else
        for indexval, substr in ipairs(tmptable) do
          if (indexval == 1) and (substr ~= '') then
            -- 0x81  = 10000000  =  10        0                 00000
            -- hex     binary       Context   Primitive value   Field: Sequence  Value: 0 (initial / match at start of string)
            tmp_result = '\x80' .. string.char(#substr) .. substr
          end

          if (indexval ~= #tmptable) and (indexval ~= 1) and (substr ~= '') then
            -- 0x81  = 10000001  =  10        0                 00001
            -- hex     binary       Context   Primitive value   Field: Sequence  Value: 1 (any / match in any position in string)
            tmp_result = tmp_result .. string.pack('Bs1', 0x81, substr)
          end

          if (indexval == #tmptable) and (substr ~= '') then
            -- 0x82  = 10000010  =  10        0                 00010
            -- hex     binary       Context   Primitive value   Field: Sequence  Value: 2 (final / match at end of string)
            tmp_result = tmp_result .. string.pack('Bs1', 0x82, substr)
          end
        end
      end

      val = asn1.ASN1Encoder:encodeSeq( tmp_result )

    elseif ( filter.op == FILTER['extensibleMatch'] ) then

      local tmptable = stringaux.strsplit(':=', filter.val)
      local tmp_result = ''
      local OID, bitmask

      if ( tmptable[1] ~= nil ) then
        OID = tmptable[1]
      else
        return false, ("ERROR: Invalid extensibleMatch query format")
      end

      if ( tmptable[2] ~= nil ) then
        bitmask = tmptable[2]
      else
        return false, ("ERROR: Invalid extensibleMatch query format")
      end

      tmp_result = string.pack('Bs1 Bs1 Bs1 Bs1',
        -- Format and create matchingRule using OID
        -- 0x81  = 10000001  =  10        0                 00001
        -- hex     binary       Context   Primitive value   Field: matchingRule  Value: 1
        0x81, OID,

        -- Format and create type using ldap attribute
        -- 0x82  = 10000010  =  10        0                 00010
        -- hex     binary       Context   Primitive value   Field: Type          Value: 2
        0x82, filter.obj,

        -- Format and create matchValue using bitmask
        -- 0x83  = 10000011  =  10        0                 00011
        -- hex     binary       Context   Primitive value   Field: matchValue    Value: 3
        0x83, bitmask,

        -- Format and create dnAttributes, defaulting to false
        -- 0x84  = 10000100  =  10        0                 00100
        -- hex     binary       Context   Primitive value   Field: dnAttributes  Value: 4
        -- 0x00 =  boolean value, in this case false
        0x84, '\x00')

      -- Format the overall extensibleMatch block
      -- 0xa9  = 10101001  =  10        1                 01001
      -- hex     binary       Context   Constructed       Field: Filter       Value: 9 (extensibleMatch)
      return '\xa9' .. asn1.ASN1Encoder.encodeLength(#tmp_result) .. tmp_result

    else
      val = encode( filter.val )
    end

    filter_str = filter_str .. obj .. val

  end
  return encode( { _ldaptype=string.pack("B", asn1_type), filter_str } )
end

--- Converts a search result as received from searchRequest to a "result" table
--
-- Does some limited decoding of LDAP attributes
--
-- TODO: Add decoding of missing attributes
-- TODO: Add decoding of userParameters
-- TODO: Add decoding of loginHours
--
-- @param searchEntries table as returned from searchRequest
-- @return table suitable for <code>stdnse.format_output</code>
function searchResultToTable( searchEntries )
  local result = {}
  for _, v in ipairs( searchEntries ) do
    local result_part = {}
    if v.objectName and v.objectName:len() > 0 then
      result_part.name = string.format("dn: %s", v.objectName)
    else
      result_part.name = "<ROOT>"
    end

    local attribs = {}
    if ( v.attributes ~= nil ) then
      for _, attrib in ipairs( v.attributes ) do
        for i=2, #attrib do
          -- do some additional Windows decoding
          if ( attrib[1] == "objectSid" ) then
            table.insert( attribs, string.format( "%s: %s", attrib[1], convertObjectSid( attrib[i] ) ) )
          elseif ( attrib[1] == "objectGUID") then
            local o = {string.unpack(("B"):rep(16), attrib[i] )}
            table.insert( attribs, string.format( "%s: %x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x",
              attrib[1], o[4], o[3], o[2], o[1], table.unpack(o, 5, 16)))
          elseif ( attrib[1] == "lastLogon" or attrib[1] == "lastLogonTimestamp" or attrib[1] == "pwdLastSet" or attrib[1] == "accountExpires" or attrib[1] == "badPasswordTime"  ) then
            table.insert( attribs, string.format( "%s: %s", attrib[1], convertADTimeStamp(attrib[i]) ) )
          elseif ( attrib[1] == "whenChanged" or attrib[1] == "whenCreated" or attrib[1] == "dSCorePropagationData" ) then
            table.insert( attribs, string.format( "%s: %s", attrib[1], convertZuluTimeStamp(attrib[i]) ) )
          else
            table.insert( attribs, string.format( "%s: %s", attrib[1], attrib[i] ) )
          end
        end
      end
      table.insert( result_part, attribs )
    end
    table.insert( result, result_part )
  end
  return result
end

--- Saves a search result as received from searchRequest to a file
--
-- Does some limited decoding of LDAP attributes
--
-- TODO: Add decoding of missing attributes
-- TODO: Add decoding of userParameters
-- TODO: Add decoding of loginHours
--
-- @param searchEntries table as returned from searchRequest
-- @param filename the name of a save to save results to
-- @return table suitable for <code>stdnse.format_output</code>
function searchResultToFile( searchEntries, filename )

  local f = io.open( filename, "w")

  if ( not(f) ) then
    return false, ("ERROR: Failed to open file (%s)"):format(filename)
  end

  -- Build table structure.  Using a multi pass approach ( build table then populate table )
  -- because the objects returned may not necessarily have the same number of attributes
  -- making single pass CSV output generation problematic.
  -- Unfortunately the searchEntries table passed to this function is not organized in a
  -- way that make particular attributes for a given hostname directly addressable.
  --
  -- At some point restructuring the searchEntries table may be a good optimization target

  -- build table of attributes
  local attrib_table = {}
  for _, v in ipairs( searchEntries ) do
    if ( v.attributes ~= nil ) then
      for _, attrib in ipairs( v.attributes ) do
        for i=2, #attrib do
          if ( attrib_table[attrib[1]] == nil ) then
            attrib_table[attrib[1]] = ''
          end
        end
      end
    end
  end

  -- build table of hosts
  local host_table = {}
  for _, v in ipairs( searchEntries ) do
    if v.objectName and v.objectName:len() > 0 then
      local host = {}

      if v.objectName and v.objectName:len() > 0 then
        -- use a copy of the table here, assigning attrib_table into host_table
        -- links the values so setting it for one host changes the specific attribute
        -- values for all hosts.
        host_table[v.objectName] = {attributes = copyTable(attrib_table) }
      end
    end
  end

  -- populate the host table with values for each attribute that has valid data
  for _, v in ipairs( searchEntries ) do
    if ( v.attributes ~= nil ) then
      for _, attrib in ipairs( v.attributes ) do
        for i=2, #attrib do
          -- do some additional Windows decoding
          if ( attrib[1] == "objectSid" ) then
            host_table[string.format("%s", v.objectName)].attributes[attrib[1]] = string.format( "%s", convertObjectSid(attrib[i]))

          elseif ( attrib[1] == "objectGUID") then
            local o = {string.unpack(("B"):rep(16), attrib[i] )}
            host_table[string.format("%s", v.objectName)].attributes[attrib[1]] = string.format(
              "%s: %x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x",
              attrib[1], o[4], o[3], o[2], o[1], table.unpack(o, 5, 16))

          elseif ( attrib[1] == "lastLogon" or attrib[1] == "lastLogonTimestamp" or attrib[1] == "pwdLastSet" or attrib[1] == "accountExpires" or attrib[1] == "badPasswordTime" ) then
            host_table[string.format("%s", v.objectName)].attributes[attrib[1]] = convertADTimeStamp(attrib[i])

          elseif ( attrib[1] == "whenChanged" or attrib[1] == "whenCreated" or attrib[1] == "dSCorePropagationData" ) then
            host_table[string.format("%s", v.objectName)].attributes[attrib[1]] = convertZuluTimeStamp(attrib[i])

          else
            host_table[v.objectName].attributes[attrib[1]] = string.format( "%s", attrib[i] )
          end

        end
      end
    end
  end

  -- write the new, fully populated table out to CSV

  -- initialize header row
  local output = "\"name\""
  for attribute, value in pairs(attrib_table) do
    output = output .. ",\"" .. attribute .. "\""
  end
  output = output .. "\n"

  -- gather host data from fields, add to output.
  for name, attribs in pairs(host_table) do
    output = output .. "\"" .. name .. "\""
    local host_attribs = attribs.attributes
    for attribute, value in pairs(attrib_table) do
      output = output .. ",\"" .. host_attribs[attribute] .. "\""
    end
    output = output .. "\n"
  end

  -- write the output to file
  if ( not(f:write( output .."\n" ) ) ) then
    f:close()
    return false, ("ERROR: Failed to write file (%s)"):format(filename)
  end

  f:close()
  return true
end


--- Extract naming context from a search response
--
-- @param searchEntries table containing searchEntries from a searchResponse
-- @param attributeName string containing the attribute to extract
-- @return table containing the attribute values
function extractAttribute( searchEntries, attributeName )
  local attributeTbl = {}
  for _, v in ipairs( searchEntries ) do
    if ( v.attributes ~= nil ) then
      for _, attrib in ipairs( v.attributes ) do
        local attribType = attrib[1]
        for i=2, #attrib do
          if ( attribType:upper() == attributeName:upper() ) then
            table.insert( attributeTbl, attrib[i])
          end
        end
      end
    end
  end
  return ( #attributeTbl > 0 and attributeTbl or nil )
end

--- Convert Microsoft Active Directory timestamp format to a human readable form
--  These values store time values in 100 nanoseconds segments from 01-Jan-1601
--
-- @param timestamp Microsoft Active Directory timestamp value
-- @return string containing human readable form
function convertADTimeStamp(timestamp)

  local result = 0
  -- Windows cannot represent this time, so we pre-calculated it:
  -- seconds since 1601/1/1 adjusted for local offset
  local base_time = -11644473600 - datetime.utc_offset()

  timestamp = tonumber(timestamp)

  if (timestamp and timestamp > 0) then

    -- The result value was 3036 seconds off what Microsoft says it should be.
    -- I have been unable to find an explanation for this, and have resorted to
    -- manually adjusting the formula.

    result = ( timestamp //  10000000 ) - 3036
    result = result + base_time
    result = datetime.format_timestamp(result, 0)
  else
    result = 'Never'
  end

  return result

end

--- Converts a non-delimited Zulu timestamp format to a human readable form
--  For example 20110904003302.0Z becomes 2001/09/04 00:33:02 UTC
--
--
-- @param timestamp in Zulu format without separators
-- @return string containing human readable form
function convertZuluTimeStamp(timestamp)

  if ( type(timestamp) == 'string' and string.sub(timestamp,-3) == '.0Z' ) then

    local year  = string.sub(timestamp,1,4)
    local month = string.sub(timestamp,5,6)
    local day   = string.sub(timestamp,7,8)
    local hour  = string.sub(timestamp,9,10)
    local mins  = string.sub(timestamp,11,12)
    local secs  = string.sub(timestamp,13,14)
    local result = year .. "/" .. month .. "/" .. day .. " " .. hour .. ":" .. mins .. ":" .. secs .. " UTC"

    return result

  else
    return 'Invalid date format'
  end

end

--- Converts the objectSid Active Directory attribute
--  from hex to a human readable string
--
--  Example: 1-5-21-542885397-2936741293-3965599772-500
--
-- @param hex string form of objectSid from LDAP response
-- @return string containing human readable form
function convertObjectSid(data)

  local pos, revision, auth, sub_auth_size, sub_auth, result

  revision, pos = string.unpack('I1', data, 1)
  sub_auth_size, pos = string.unpack('I1', data, pos)
  auth, pos = string.unpack('>I6', data, pos)

  sub_auth = ''
  local tmp
  local cnt = 0
  while (cnt < sub_auth_size) do
    tmp, pos = string.unpack('<I4', data, pos)
    sub_auth = sub_auth .. '-' .. tmp
    cnt = cnt + 1
  end

  result = revision .. '-' .. auth .. sub_auth
  return result

end

--- Creates a copy of a table
--
--
-- @param targetTable  table object to copy
-- @return table object containing copy of original
function copyTable(targetTable)
  local temp = { }
  for key, val in pairs(targetTable) do
    temp[key] = val
  end
  return setmetatable(temp, getmetatable(targetTable))
end

return _ENV;
