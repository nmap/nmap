--- SNMP functions.
--
-- @args snmpcommunity The community string to use. If not given, it is
-- <code>"public"</code>, or whatever is passed to <code>buildPacket</code>.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html


module(... or "snmp",package.seeall)


require("bit")

---
-- Encodes an Integer according to ASN.1 basic encoding rules.
-- @param val Value to be encoded.
-- @return Encoded integer.
local function encodeInt(val)
   local lsb = 0
   if val > 0 then
      local valStr = ""
      while (val > 0) do
	 lsb = math.mod(val, 256)
	 valStr = valStr .. bin.pack("C", lsb)
	 val = math.floor(val/256)
      end
      if lsb > 127 then -- two's complement collision
	 valStr = valStr .. bin.pack("H", "00")
      end

      return string.reverse(valStr)
   elseif val < 0 then
      local i = 1
      local tcval = val + 256 -- two's complement
      while tcval <= 127 do
	 tcval = tcval + (math.pow(256, i) * 255)
	 i = i+1
      end
      local valStr = ""
      while (tcval > 0) do
	 lsb = math.mod(tcval, 256)
	 valStr = valStr .. bin.pack("C", lsb)
	 tcval = math.floor(tcval/256)
      end
      return string.reverse(valStr)
   else -- val == 0
      return bin.pack("x")
   end
end


---
-- Encodes the length part of a ASN.1 encoding triplet using the "primitive,
-- definite-length" method.
-- @param val Value to be encoded.
-- @return Encoded length value.
local function encodeLength(len)
   if len < 128 then
      return string.char(len)
   else
      local parts = {}

      while len > 0 do
         parts[#parts + 1] = string.char(bit.mod(len, 256))
         len = bit.rshift(len, 8)
      end

      assert(#parts < 128)
      return string.char(#parts + 0x80) .. string.reverse(table.concat(parts))
   end
end


-- Encode one component of an OID as a byte string. 7 bits of the component are
-- stored in each octet, most significant first, with the eigth bit set in all
-- octets but the last. These encoding rules come from
-- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
-- IDENTIFIER.
local function encode_oid_component(n)
  local parts = {}
  parts[1] = string.char(bit.mod(n, 128))
  while n >= 128 do
    n = bit.rshift(n, 7)
    parts[#parts + 1] = string.char(bit.mod(n, 128) + 0x80)
  end
  return string.reverse(table.concat(parts))
end


---
-- Encodes a given value according to ASN.1 basic encoding rules for SNMP
-- packet creation.
-- @param val Value to be encoded.
-- @return Encoded value.
function encode(val)
   local vtype = type(val)
   if (vtype == 'number') then
      local ival = encodeInt(val)
      local len = encodeLength(string.len(ival))
      return bin.pack('HAA', '02', len, ival)
   end
   if (vtype == 'string') then
      local len = encodeLength(string.len(val))
      return bin.pack('HAA', '04', len, val)
   end
   if (vtype == 'nil' or vtype == 'boolean') then
      return bin.pack('H', '05 00')
   end
   if (vtype == 'table') then -- complex data types
      if val._snmp == '06' then -- OID
	 local oidStr = string.char(val[1]*40 + val[2])
	 for i = 3, #val do
	    oidStr = oidStr .. encode_oid_component(val[i])
	 end 
	 return bin.pack("HAA", '06', encodeLength(#oidStr), oidStr) 
      elseif (val._snmp == '40') then -- ipAddress
	 return bin.pack("HC4", '40 04', unpack(val))
      elseif (val._snmp == '41') then -- counter
	 local cnt = encodeInt(val[1])
	 return bin.pack("HAA", val._snmp, encodeLength(string.len(cnt)), cnt)
      elseif (val._snmp == '42') then -- gauge
	 local gauge = encodeInt(val[1])
	 return bin.pack("HAA", val._snmp, encodeLength(string.len(gauge)), gauge)
      elseif (val._snmp == '43') then -- timeticks
	 local ticks = encodeInt(val[1])
	 return bin.pack("HAA", val._snmp, encodeLength(string.len(ticks)), ticks)
      elseif (val._snmp == '44') then -- opaque
	 return bin.pack("HAA", val._snmp, encodeLength(string.len(val[1])), val[1])
      end
      local encVal = ""
      for _, v in ipairs(val) do
	 encVal = encVal .. encode(v) -- todo: buffer?
      end
      local tableType = bin.pack("H", "30")
      if (val["_snmp"]) then 
	 tableType = bin.pack("H", val["_snmp"]) 
      end
      return bin.pack('AAA', tableType, encodeLength(string.len(encVal)), encVal)
   end
   return ''
end


---
-- Decodes length part of encoded value according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding.
-- @return The length of the following value.
local function decodeLength(encStr, pos)
   local elen
   pos, elen = bin.unpack('C', encStr, pos)
   if (elen > 128) then
      elen = elen - 128
      local elenCalc = 0
      local elenNext
      for i = 1, elen do
	 elenCalc = elenCalc * 256
	 pos, elenNext = bin.unpack("C", encStr, pos)
	 elenCalc = elenCalc + elenNext
      end
      elen = elenCalc
   end
   return pos, elen
end


---
-- Decodes an Integer according to ASN.1 basic encoding rules.
-- @param encStr Encoded string.
-- @param len Length of integer in bytes.
-- @param pos Current position in the string.
-- @return The position after decoding.
-- @return The decoded integer.
local function decodeInt(encStr, len, pos)
   local hexStr
   pos, hexStr = bin.unpack("H" .. len, encStr, pos)
   local value = tonumber(hexStr, 16)
   if (value >= math.pow(256, len)/2) then
      value = value - math.pow(256, len)
   end
   return pos, value
end

-- Decode one component of an OID from a byte string. 7 bits of the component
-- are stored in each octet, most significant first, with the eigth bit set in
-- all octets but the last. These encoding rules come from
-- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
-- IDENTIFIER.
local function decode_oid_component(encStr, pos)
   local octet
   local n = 0

   repeat
      pos, octet = bin.unpack("C", encStr, pos)
      n = n * 128 + bit.band(0x7F, octet)
   until octet < 128

   return pos, n
end

--- Decodes an OID from a sequence of bytes.
--
-- @param encStr Encoded string.
-- @param len Length of sequence in bytes.
-- @param pos Current position in the string.
-- @return The position after decoding.
-- @return The OID as an array.
local function decodeOID(encStr, len, pos)
   local last
   local oid = {}
   local octet

   last = pos + len - 1
   if pos <= last then
      oid._snmp = '06'
      pos, octet = bin.unpack("C", encStr, pos)
      oid[2] = math.mod(octet, 40)
      octet = octet - oid[2]
      oid[1] = octet/40
   end

   while pos <= last do
      local c
      pos, c = decode_oid_component(encStr, pos)
      oid[#oid + 1] = c
   end
 
   return pos, oid
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
   local i = 1
   local sStr
   pos, sStr = bin.unpack("A" .. len, encStr, pos)
   while (sPos < len) do
      local newSeq
      sPos, newSeq = decode(sStr, sPos)
      table.insert(seq, newSeq)
      i = i + 1
   end
   return pos, seq
end

---
-- Decodes an SNMP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding
-- @return The decoded value(s).
function decode(encStr, pos)
   local etype, elen
   pos, etype = bin.unpack("H1", encStr, pos)
   pos, elen = decodeLength(encStr, pos)
   if (etype == "02") then -- INTEGER
      return decodeInt(encStr, elen, pos)
      
   elseif (etype == "04") then -- STRING
      return bin.unpack("A" .. elen, encStr, pos)
      
   elseif (etype == "05") then -- NULL
      return pos, false

   elseif (etype == "06") then -- OID
      return decodeOID( encStr, elen, pos )

   elseif (etype == "30") then -- sequence
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      return pos, seq

   elseif (etype == "A0") then -- getReq
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      seq._snmp = etype
      return pos, seq

   elseif (etype == "A1") then -- getNextReq
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      seq._snmp = etype
      return pos, seq

   elseif (etype == "A2") then -- getResponse
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      seq._snmp = etype
      return pos, seq

   elseif (etype == "A3") then -- setReq
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      seq._snmp = etype
      return pos, seq
   elseif (etype == "A4") then -- Trap
      local seq
      pos, seq = decodeSeq(encStr, elen, pos)
      seq._snmp = etype
      return pos, seq
   elseif (etype == '40') then -- App: IP-Address
      local ip = {}
      pos, ip[1], ip[2], ip[3], ip[4] = bin.unpack("C4", encStr, pos)
      ip._snmp = '40'
      return pos, ip
   elseif (etype == '41') then -- App: counter
      local cnt = {}
      pos, cnt[1] = decodeInt(encStr, elen, pos)
      cnt._snmp = '41'
      return pos, cnt
   elseif (etype == '42') then -- App: gauge
      local gauge = {}
      pos, gauge[1] = decodeInt(encStr, elen, pos)
      gauge._snmp = '42'
      return pos, gauge
   elseif (etype == '43') then -- App: TimeTicks
      local ticks = {}
      pos, ticks[1] = decodeInt(encStr, elen, pos)
      ticks._snmp = '43'
      return pos, ticks
   elseif (etype == '44') then -- App: opaque
      local opaque = {}
      pos, opaque[1] = bin.unpack("A" .. elen, encStr, pos)
      opaque._snmp = '44'
      return pos, opaque
   end
   return pos, nil
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

   if not options.reqId then options.reqId = math.mod(nmap.clock_ms(), 65000) end
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

	 if not options.reqId then options.reqId = math.mod(nmap.clock_ms(), 65000) end
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

	 if not options.reqId then options.reqId = math.mod(nmap.clock_ms(), 65000) end
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
   if not options.reqId then options.reqId = math.mod(nmap.clock_ms(), 65000) end
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
   if type(result) == "table" and result[1] and result[1][1] then return result[1][1]
   else return nil
   end
end
