---
-- SNMP functions.
--
-- @args snmpcommunity The community string to use. If not given, it is
-- <code>"public"</code>, or whatever is passed to <code>buildPacket</code>.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local asn1 = require "asn1"
local bin = require "bin"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("snmp", stdnse.seeall)


-- SNMP ASN.1 Encoders
local tagEncoder = {}

-- Override the boolean encoder
tagEncoder['boolean'] = function(self, val)
	return bin.pack('H', '05 00')
end

-- Complex tag encoders
tagEncoder['table'] = function(self, val)
	if val._snmp == '06' then -- OID
		local oidStr = string.char(val[1]*40 + val[2])
		for i = 3, #val do
   			oidStr = oidStr .. self.encode_oid_component(val[i])
		end 
		return bin.pack("HAA", '06', self.encodeLength(#oidStr), oidStr) 

 	elseif (val._snmp == '40') then -- ipAddress
		return bin.pack("HC4", '40 04', table.unpack(val))
 	
    -- counter or gauge or timeticks or opaque
	elseif (val._snmp == '41' or val._snmp == '42' or val._snmp == '43' or val._snmp == '44') then
		local val = self:encodeInt(val[1])
		return bin.pack("HAA", val._snmp, self.encodeLength(#val), val)
	end
	
	local encVal = ""
	for _, v in ipairs(val) do
		encVal = encVal .. self:encode(v) -- todo: buffer?
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
	local vtype = type(val)
	local encoder = asn1.ASN1Encoder:new()
	encoder:registerTagEncoders( tagEncoder )
   	

	local encVal = encoder:encode(val)
		
	if encVal then
		return encVal
	end
	
	return ''
end

-- SNMP ASN.1 Decoders
local tagDecoder = {}

-- Application specific tags
--
-- IP Address

-- Response-PDU
-- TOOD: Figure out how to remove these dependancies
tagDecoder["A2"] = function( self, encStr, elen, pos )
   local seq = {}
 
   pos, seq = self:decodeSeq(encStr, elen, pos)
   seq._snmp = "A2"
   return pos, seq
end

tagDecoder["40"] = function( self, encStr, elen, pos )
	local ip = {}
	pos, ip[1], ip[2], ip[3], ip[4] = bin.unpack("C4", encStr, pos)
	ip._snmp = '40'
	return pos, ip
end

---
-- Decodes an SNMP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding
-- @return The decoded value(s).
function decode(encStr, pos)
	local decoder = asn1.ASN1Decoder:new()
	
	if ( #tagDecoder == 0 ) then
		decoder:registerBaseDecoders()
		-- Application specific tags
		-- tagDecoder["40"] = decoder.decoder["06"]  -- IP Address; same as OID
		tagDecoder["41"] = decoder.decoder["02"]  -- Counter; same as Integer
		tagDecoder["42"] = decoder.decoder["02"]  -- Gauge
		tagDecoder["43"] = decoder.decoder["02"]  -- TimeTicks
		tagDecoder["44"] = decoder.decoder["04"]  -- Opaque; same as Octet String
		tagDecoder["45"] = decoder.decoder["06"]  -- NsapAddress
		tagDecoder["46"] = decoder.decoder["02"]  -- Counter64
		tagDecoder["47"] = decoder.decoder["02"]  -- UInteger32

		-- Context specific tags
		tagDecoder["A0"] = decoder.decoder["30"]  -- GetRequest-PDU
		tagDecoder["A1"] = decoder.decoder["30"]  -- GetNextRequest-PDU
		--tagDecoder["A2"] = decoder.decoder["30"]  -- Response-PDU
		tagDecoder["A3"] = decoder.decoder["30"]  -- SetRequest-PDU
		tagDecoder["A4"] = decoder.decoder["30"]  -- Trap-PDU
		tagDecoder["A5"] = decoder.decoder["30"]  -- GetBulkRequest-PDU
		tagDecoder["A6"] = decoder.decoder["30"]  -- InformRequest-PDU (not implemented here yet)
		tagDecoder["A7"] = decoder.decoder["30"]  -- SNMPv2-Trap-PDU (not implemented here yet)
	end
	
	
	decoder:registerTagDecoders( tagDecoder )

   return decoder:decode( encStr, pos )
end

---
-- Decodes an SNMP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The decoded value(s).
function dec(encStr, pos)
   local result
   local _
   _, result = decode(encStr, pos)
   return result
end

---
-- Create an SNMP packet.
-- @param PDU SNMP Protocol Data Unit to be encapsulated in the packet.
-- @param version SNMP version, default <code>0</code> (SNMP V1).
-- @param commStr community string, if not already supplied in registry or as
-- the <code>snmpcommunity</code> script argument.
function buildPacket(PDU, version, commStr)
   local comm = nmap.registry.args.snmpcommunity
   if (not comm) then comm = nmap.registry.snmpcommunity end
   if (not comm) then comm = commStr end
   if (not comm) then comm = "public" end

   if (not version) then version = 0 end
   local packet = {}
   packet[1] = version
   packet[2] = comm
   packet[3] = PDU
   return packet
end


--- 
-- Create an SNMP Get Request PDU.
-- @param options A table containing the following fields:
-- * <code>"reqId"</code>: Request ID.
-- * <code>"err"</code>: Error.
-- * <code>"errIdx"</code>: Error index.
-- @param ... Object identifiers to be queried.
-- @return Table representing PDU.
function buildGetRequest(options, ...)
   if not options then options = {} end

   if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
   if not options.err then options.err = 0 end
   if not options.errIdx then options.errIdx = 0 end

   local req = {}
   req._snmp = 'A0'
   req[1] = options.reqId
   req[2] = options.err
   req[3] = options.errIdx
   
   local payload = {}
   for i=1, select('#', ...) do
      payload[i] = {}
      payload[i][1] = select(i, ...)
      if type(payload[i][1]) == "string" then
	 payload[i][1] = str2oid(payload[i][1])
      end
      payload[i][2] = false
   end
   req[4] = payload
   return req
end


--- 
-- Create an SNMP Get Next Request PDU.
-- @param options A table containing the following fields:
-- * <code>"reqId"</code>: Request ID.
-- * <code>"err"</code>: Error.
-- * <code>"errIdx"</code>: Error index.
-- @param ... Object identifiers to be queried.
-- @return Table representing PDU.
function buildGetNextRequest(options, ...)
   if not options then options = {} end

   if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
   if not options.err then options.err = 0 end
   if not options.errIdx then options.errIdx = 0 end

   local req = {}
   req._snmp = 'A1'
   req[1] = options.reqId
   req[2] = options.err
   req[3] = options.errIdx
   
   local payload = {}
   for i=1, select('#', ...) do
      payload[i] = {}
      payload[i][1] = select(i, ...)
      if type(payload[i][1]) == "string" then
	     payload[i][1] = str2oid(payload[i][1])
      end
      payload[i][2] = false
   end
   req[4] = payload
   return req
end

--- 
-- Create an SNMP Set Request PDU.
--
-- Takes one OID/value pair or an already prepared table.
-- @param options A table containing the following keys and values:
-- * <code>"reqId"</code>: Request ID.
-- * <code>"err"</code>: Error.
-- * <code>"errIdx"</code>: Error index.
-- @param oid Object identifiers of object to be set.
-- @param value To which value object should be set. If given a table, use the
-- table instead of OID/value pair.
-- @return Table representing PDU.
function buildSetRequest(options, oid, value)
   if not options then options = {} end

	 if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
   if not options.err then options.err = 0 end
   if not options.errIdx then options.errIdx = 0 end

   local req = {}
   req._snmp = 'A3'
   req[1] = options.reqId
   req[2] = options.err
   req[3] = options.errIdx

   if (type(value) == "table") then
      req[4] = value
   else 
      local payload = {}
      if (type(oid) == "string") then
	 payload[1] = str2oid(oid)
      else
	 payload[1] = oid
      end
      payload[2] = value
      req[4] = {}
      req[4][1] = payload
   end
   return req
end

--- 
-- Create an SNMP Trap PDU.
-- @return Table representing PDU
function buildTrap(enterpriseOid, agentIp, genTrap, specTrap, timeStamp)
   local req = {}
   req._snmp = 'A4'
   if (type(enterpriseOid) == "string") then 
      req[1] = str2oid(enterpriseOid)
   else
      req[1] = enterpriseOid
   end
   req[2] = {}
   req[2]._snmp = '40'
   for n in string.gmatch(agentIp, "%d+") do
      table.insert(req[2], tonumber(n))
   end
   req[3] = genTrap
   req[4] = specTrap

   req[5] = {}
   req[5]._snmp = '43'
   req[5][1] = timeStamp

   req[6] = {}

   return req
end

--- 
-- Create an SNMP Get Response PDU.
--
-- Takes one OID/value pair or an already prepared table.
-- @param options A table containing the following keys and values:
-- * <code>"reqId"</code>: Request ID.
-- * <code>"err"</code>: Error.
-- * <code>"errIdx"</code>: Error index.
-- @param oid Object identifiers of object to be sent back.
-- @param value If given a table, use the table instead of OID/value pair.
-- @return Table representing PDU.
function buildGetResponse(options, oid, value) 
   if not options then options = {} end

   -- if really a response, should use reqId of request!
   if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
   if not options.err then options.err = 0 end
   if not options.errIdx then options.errIdx = 0 end

   local resp = {}
   resp._snmp = 'A2'
   resp[1] = options.reqId
   resp[2] = options.err
   resp[3] = options.errIdx

   if (type(value) == "table") then
      resp[4] = value
   else 

      local payload = {}
      if (type(oid) == "string") then
	 payload[1] = str2oid(oid)
      else
	 payload[1] = oid
      end
      payload[2] = value
      resp[4] = {}
      resp[4][1] = payload
   end
   return resp
end

--- 
-- Transforms a string into an object identifier table.
-- @param oidStr Object identifier as string, for example
-- <code>"1.3.6.1.2.1.1.1.0"</code>.
-- @return Table representing OID.
function str2oid(oidStr)
   local oid = {}
   for n in string.gmatch(oidStr, "%d+") do
      table.insert(oid, tonumber(n))
   end
   oid._snmp = '06'
   return oid
end

---
-- Transforms a table representing an object identifier to a string.
-- @param oid Object identifier table.
-- @return OID string.
function oid2str(oid)
   if (type(oid) ~= "table") then return 'invalid oid' end
   return table.concat(oid, '.')
end

---
-- Transforms a table representing an IP to a string.
-- @param ip IP table.
-- @return IP string.
function ip2str(ip)
   if (type(ip) ~= "table") then return 'invalid ip' end
   return table.concat(ip, '.')
end


---
-- Transforms a string into an IP table.
-- @param ipStr IP as string.
-- @return Table representing IP.
function str2ip(ipStr)
   local ip = {}
   for n in string.gmatch(ipStr, "%d+") do
      table.insert(ip, tonumber(n))
   end
   ip._snmp = '40'
   return ip
end


---
-- Fetches values from a SNMP response.
-- @param resp SNMP Response (will be decoded if necessary).
-- @return Table with all decoded responses and their OIDs.
function fetchResponseValues(resp)
   if (type(resp) == "string") then
      local _
      _, resp = decode(resp)
   end

   if (type(resp) ~= "table") then 
      return {}
   end

   local varBind
   if (resp._snmp and resp._snmp == 'A2') then
      varBind = resp[4]
   elseif (resp[3]._snmp and resp[3]._snmp == 'A2') then
      varBind = resp[3][4]
   end

   if (varBind and type(varBind) == "table") then
      local result = {}
      for k, v in ipairs(varBind) do
	 local val = v[2]
	 if (type(v[2]) == "table") then
	    if (v[2]._snmp == '40') then
	       val = v[2][1] .. '.' .. v[2][2] .. '.' .. v[2][3] .. '.' .. v[2][4]
	    elseif (v[2]._snmp == '41') then
	       val = v[2][1]
	    elseif (v[2]._snmp == '42') then
	       val = v[2][1]
	    elseif (v[2]._snmp == '43') then
	       val = v[2][1]
	    elseif (v[2]._snmp == '44') then
	       val = v[2][1]
	    end
	 end
	 table.insert(result, {val, oid2str(v[1]), v[1]})
      end
      return result
   end
   return {}
end


---
-- Fetches the first value from a SNMP response.
-- @param response SNMP Response (will be decoded if necessary).
-- @return First decoded value of the response.
function fetchFirst(response)
	local result = fetchResponseValues(response)

	if type(result) == "table" and result[1] and result[1][1] then
		return result[1][1]
   	else 
		return nil
	end
end


--- Walks the MIB Tree
--
-- @param socket socket already connected to the server
-- @param base_oid string containing the base object ID to walk
-- @return status true on success, false on failure
-- @return table containing <code>oid</code> and <code>value</code>
function snmpWalk( socket, base_oid )
	
	local snmp_table = {}
	local oid = base_oid
	local status, err, payload
	
	while ( true ) do
		
		local value, response, snmpdata, options, item = nil, nil, nil, {}, {}
		options.reqId = 28428 -- unnecessary?
		payload = encode( buildPacket( buildGetNextRequest(options, oid) ) )

		status, err = socket:send(payload)
		if ( not( status ) ) then
			stdnse.print_debug("snmp.snmpWalk: Send failed")
			return false, err
		end
		
		status, response = socket:receive_bytes(1) 
		if ( not( status ) ) then
			-- Unless we don't have a usefull error message, don't report it
			if ( response ~= "ERROR" ) then
				stdnse.print_debug("snmp.snmpWalk: Received no answer (%s)", response)
				return false, response
			end
			return false, nil
		end
	
		snmpdata = fetchResponseValues( response )
		
		value = snmpdata[1][1]
		oid  = snmpdata[1][2]
		
		if not oid:match( base_oid ) or base_oid == oid then
			break
		end
		
		item.oid = oid
		item.value = value
		
		table.insert( snmp_table, item )
		
	end

	snmp_table.baseoid = base_oid

	return true, snmp_table
	
end

return _ENV;
