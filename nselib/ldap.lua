---
-- Library methods for handling LDAP. 
--
-- @author Patrik Karlsson
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- Credit goes out to Martin Swende who provided me with the initial code that got me started writing this.
--
-- Version 0.3
-- Created 01/12/2010 - v0.1 - Created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/28/2010 - v0.2 - Revised to fit better fit ASN.1 library
-- Revised 02/02/2010 - v0.3 - Revised to fit OO ASN.1 Library

module("ldap", package.seeall)

require("asn1")

local ldapMessageId = 1

ERROR_MSG = {}
ERROR_MSG[1]  = "Intialization of LDAP library failed."
ERROR_MSG[4]  = "Size limit exceeded."
ERROR_MSG[32] = "No such object"
ERROR_MSG[49] = "The supplied credential is invalid."

ERRORS = {
	LDAP_SUCCESS = 0,
	LDAP_SIZELIMIT_EXCEEDED = 4
}

-- Application constants
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
	if (val._ldap == '0A') then
		local ival = self.encodeInt(val[1])
		local len = self.encodeLength(#ival)
		return bin.pack('HAA', '0A', len, ival)	
	end
	if (val._ldaptype) then
		local len
		if val[1] == nil or #val[1] == 0 then
			return bin.pack('HC', val._ldaptype, 0)
		else
			len = self.encodeLength(#val[1])
			return bin.pack('HAA', val._ldaptype, len, val[1])
		end
	end
	
	local encVal = ""
  	for _, v in ipairs(val) do
 		encVal = encVal .. encode(v) -- todo: buffer?
  	end
  	local tableType = bin.pack("H", "30")
  	if (val["_snmp"]) then 
 		tableType = bin.pack("H", val["_snmp"]) 
  	end
  	return bin.pack('AAA', tableType, self.encodeLength(#encVal), encVal)
 	
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

tagDecoder["0A"] = function( self, encStr, elen, pos )
	return self.decodeInt(encStr, elen, pos)
end

-- null decoder
tagDecoder["31"] = function( self, encStr, elen, pos )
	return pos, nil
end


---
-- Decodes an LDAP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding
-- @return The decoded value(s).
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
-- @return The position after decoding.
-- @return The decoded sequence as a table.
local function decodeSeq(encStr, len, pos)
	local seq = {}
	local sPos = 1
	local sStr
	pos, sStr = bin.unpack("A" .. len, encStr, pos)
	if(sStr==nil) then 
		return pos,seq
	end
	while (sPos < len) do
		local newSeq
		sPos, newSeq = decode(sStr, sPos)
		table.insert(seq, newSeq)
	end
	return pos, seq
end

-- Encodes an LDAP Application operation and its data as a sequence
--
-- @param appno LDAP application number @see <code>APPNO</code>
-- @param isConstructed boolean true if constructed, false if primitive
-- @param data string containing the LDAP operation content
-- @return string containing the encoded LDAP operation
function encodeLDAPOp( appno, isConstructed, data )
	local encoded_str = ""
	local asn1_type = asn1.BERtoInt( asn1.BERCLASS.Application, isConstructed, appno )

	encoded_str = encode( { _ldaptype = bin.pack("A", string.format("%X", asn1_type)), data } )
	return encoded_str
end

--- Performs an LDAP Search request
--
-- This function has a concept of softerrors which populates the return tables error information
-- while returning a true status. The reason for this is that LDAP may return a number of records
-- and then finnish of with an error like SIZE LIMIT EXCEEDED. We still want to return the records
-- that were received prior to the error. In order to achieve this and not terminating the script
-- by returning a false status a true status is returned together with a table containing all searchentries.
-- This table has the <code>errorMessage</code> and <code>resultCode</code> entries set with the error information.
-- As a <code>try</code> won't catch this error it's up to the script to do so. See ldap-search.nse for an example.
--
-- @param socket socket already connected to the ldap server
-- @param params table containing at least <code>scope</code>, <code>derefPolicy</code>, <code>baseObject</code>
--        the field <code>maxObjects</code> may also be included to restrict the amount of records returned
-- @return success true or false. 
-- @return err string containing error message
function searchRequest( socket, params )

	local searchResEntries = { errorMessage="", resultCode = 0}
	local catch = function() socket:close()	stdnse.print_debug(string.format("SearchRequest failed")) end
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
	
	request = request .. encode( { _ldap='0A', params.scope } )--scope
	request = request .. encode( { _ldap='0A', params.derefPolicy } )--derefpolicy
	request = request .. encode( params.sizeLimit or 0)--sizelimit
	request = request .. encode( params.timeLimit or 0)--timelimit
	request = request .. encode( params.typesOnly or false)--TypesOnly
	
	if params.filter then
		request = request .. createFilter( params.filter )
	else
		request = request .. encode( { _ldaptype='87', "objectclass" } )-- filter : string, presence
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
			pos, len = decoder.decodeLength( data, pos )
		else
			data = data .. try( socket:receive() )
			pos, len = decoder.decodeLength( data, pos )
		end
		-- pos should be at the right position regardless if length is specified in 1 or 2 bytes
		while ( len + pos - 1 > data:len() ) do
			data = data .. try( socket:receive() )
		end
		
		pos, messageId = decode( data, pos )
		pos, tmp = bin.unpack("C", data, pos)
		pos, len = decoder.decodeLength( data, pos )
		ldapOp = asn1.intToBER( tmp )
		searchResEntry = {}
		
		if ldapOp.number == APPNO.SearchResDone then
			pos, searchResEntry.resultCode = decode( data, pos )
			-- errors may occur after a large amount of data has been received (eg. size limit exceeded)
			-- we want to be able to return the data received prior to this error to the user
			-- however, we also need to alert the user of the error. This is achieved through "softerrors"
			-- softerrors populate the error fields of the table while returning a true status
			-- this allows for the caller to output data while still being able to catch the error
			if ( searchResEntry.resultCode ~= 0 ) then
				local error_msg
				pos, searchResEntry.matchedDN = decode( data, pos )
				pos, searchResEntry.errorMessage = decode( data, pos )
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

		pos, searchResEntry.objectName = decode( data, pos )
		if ldapOp.number == APPNO.SearchResponse then
			pos, searchResEntry.attributes = decode( data, pos )
					
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


--- Attempts to bind to the server using the credentials given
--
-- @param socket socket already connected to the ldap server
-- @param params table containing <code>version</code>, <code>username</code> and <code>password</code>
-- @return success true or false
-- @return err string containing error message
function bindRequest( socket, params )

	local catch = function() socket:close()	stdnse.print_debug(string.format("bindRequest failed"))	end
	local try = nmap.new_try(catch)
	local ldapAuth = encode( { _ldaptype = 80, params.password } )
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

	pos, packet_len = decoder.decodeLength( packet, 2 )
	pos, response.messageID = decode( packet, pos )	
	pos, tmp = bin.unpack("C", packet, pos)
	pos, len = decoder.decodeLength( packet, pos )
	response.protocolOp = asn1.intToBER( tmp )

	if response.protocolOp.number ~= APPNO.BindResponse then
		return false, string.format("Recieved incorrect Op in packet: %d, expected %d", response.protocolOp.number, APPNO.BindResponse)
	end
	
	pos, response.resultCode = decode( packet, pos )
	
	if ( response.resultCode ~= 0 ) then
		local error_msg
		pos, response.matchedDN = decode( packet, pos )
		pos, response.errorMessage = decode( packet, pos )
		error_msg = ERROR_MSG[response.resultCode] 
		return false, string.format("Error: %s\nDetails: %s", error_msg or "", response.errorMessage or "" )
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
	local catch = function() socket:close()	stdnse.print_debug(string.format("bindRequest failed"))	end
	local try = nmap.new_try(catch)

	local encoder = asn1.ASN1Encoder:new()
	encoder:registerTagEncoders(tagEncoder)

	ldapMessageId = ldapMessageId +1
	ldapMsg = encode( ldapMessageId )
	ldapMsg = ldapMsg .. encodeLDAPOp( APPNO.UnbindRequest, false, nil)
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
		local val = encode( filter.val )

		filter_str = filter_str .. obj .. val
	end
	return encode( { _ldaptype=bin.pack("A", string.format("%X", asn1_type)), filter_str } )
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
						table.insert( attribs, string.format( "%s: %d", attrib[1], decode( attrib[i] ) ) )
					elseif ( attrib[1] == "objectGUID") then
						local _, o1, o2, o3, o4, o5, o6, o7, o8, o9, oa, ob, oc, od, oe, of = bin.unpack("C16", attrib[i] )
						table.insert( attribs, string.format( "%s: %x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x", attrib[1], o4, o3, o2, o1, o5, o6, o7, o8, o9, oa, ob, oc, od, oe, of ) )
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
