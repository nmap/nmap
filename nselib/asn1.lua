---
-- ASN.1 functions.
--
-- Large chunks of this code have been ripped right out from <code>snmp.lua</code>.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- @author Patrik Karlsson
--

-- Version 0.3
-- Created 01/12/2010 - v0.1 - Created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/28/2010 - v0.2 - Adapted to create a framework for SNMP, LDAP and future protocols
-- Revised 02/02/2010 - v0.3 - Changes:	o Re-designed so that ASN1Encoder and ASN1Decoder are separate classes
--										o Each script or library should now create it's own Encoder and Decoder instance
--

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("asn1", stdnse.seeall)

BERCLASS = {
	Universal = 0,
	Application = 64,
	ContextSpecific = 128,
	Private = 192
}

--- The decoder class
--
ASN1Decoder = {

	new = function(self,o)
            o = o or {}
            setmetatable(o, self)
            self.__index = self
            return o
    end,

	--- Tells the decoder to stop if it detects an error while decoding
	-- this should probably be the default, but some scripts depend on being
	-- able to decode stuff while lacking proper ASN1 decoding functions.
	--
	-- @param val boolean, true if decoding should stop on error,
	--        otherwise false (default)
	setStopOnError = function(self, val)
		self.stoponerror = val
	end,
		
	--- Registers the base simple type decoders
	-- 
	registerBaseDecoders = function(self)
		self.decoder = {}
	
		-- Boolean
		self.decoder["01"] = function( self, encStr, elen, pos )
			local val = bin.unpack("H", encStr, pos)
			if val ~= "FF" then
				return pos, true
			else
				return pos, false
			end
		end

		-- Integer
		self.decoder["02"] = function( self, encStr, elen, pos )
			return self.decodeInt(encStr, elen, pos)
		end

		-- Octet String
		self.decoder["04"] = function( self, encStr, elen, pos )
			return bin.unpack("A" .. elen, encStr, pos)
		end

		-- Null
		self.decoder["05"] = function( self, encStr, elen, pos )
			return pos, false
		end

		-- Object Identifier
		self.decoder["06"] = function( self, encStr, elen, pos )
			return self:decodeOID( encStr, elen, pos )
		end
		
		-- Context specific tags
		--
		self.decoder["30"] = function( self, encStr, elen, pos )
		  return self:decodeSeq(encStr, elen, pos)
		end
	end,

	--- Allows for registration of additional tag decoders
	--
	-- @param tagDecoders table containing decoding functions @see tagDecoders
	registerTagDecoders = function(self, tagDecoders)
		self:registerBaseDecoders()
		for k, v in pairs(tagDecoders) do
			self.decoder[k] = v
		end
	end,

	--- Decodes the ASN.1's built-in simple types
	-- 
	-- @param encStr Encoded string.
	-- @param pos Current position in the string.
	-- @return The position after decoding
	-- @return The decoded value(s).
	decode = function(self, encStr, pos)

		local etype, elen
		local newpos = pos

	   	newpos, etype = bin.unpack("H1", encStr, newpos)
	   	newpos, elen = self.decodeLength(encStr, newpos)

		if self.decoder[etype] then
			return self.decoder[etype]( self, encStr, elen, newpos )
	   	else
		  	stdnse.print_debug("no decoder for etype: " .. etype)
	      	return newpos, nil
	   	end
	end,

	---
	-- Decodes length part of encoded value according to ASN.1 basic encoding
	-- rules.
	-- @param encStr Encoded string.
	-- @param pos Current position in the string.
	-- @return The position after decoding.
	-- @return The length of the following value.
	decodeLength = function(encStr, pos)
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
	end,

	---
	-- Decodes a sequence according to ASN.1 basic encoding rules.
	-- @param encStr Encoded string.
	-- @param len Length of sequence in bytes.
	-- @param pos Current position in the string.
	-- @return The position after decoding.
	-- @return The decoded sequence as a table.
	decodeSeq = function(self, encStr, len, pos)
	   local seq = {}
	   local sPos = 1
	   local sStr
	   pos, sStr = bin.unpack("A" .. len, encStr, pos)
	   while (sPos < len) do
	      local newSeq
	      sPos, newSeq = self:decode(sStr, sPos)
          if ( not(newSeq) and self.stoponerror ) then break end
	      table.insert(seq, newSeq)
	   end
	   return pos, seq
	end,
	
	-- Decode one component of an OID from a byte string. 7 bits of the component
	-- are stored in each octet, most significant first, with the eigth bit set in
	-- all octets but the last. These encoding rules come from
	-- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
	-- IDENTIFIER.
	decode_oid_component = function(encStr, pos)
	   local octet
	   local n = 0

	   repeat
	      pos, octet = bin.unpack("C", encStr, pos)
	      n = n * 128 + bit.band(0x7F, octet)
	   until octet < 128

	   return pos, n
	end,
	
	--- Decodes an OID from a sequence of bytes.
	--
	-- @param encStr Encoded string.
	-- @param len Length of sequence in bytes.
	-- @param pos Current position in the string.
	-- @return The position after decoding.
	-- @return The OID as an array.
 	decodeOID = function(self, encStr, len, pos)
	   local last
	   local oid = {}
	   local octet

	   last = pos + len - 1
	   if pos <= last then
	      oid._snmp = '06'
	      pos, octet = bin.unpack("C", encStr, pos)
	      oid[2] = math.fmod(octet, 40)
	      octet = octet - oid[2]
	      oid[1] = octet/40
	   end

	   while pos <= last do
	      local c
	      pos, c = self.decode_oid_component(encStr, pos)
	      oid[#oid + 1] = c
	   end

	   return pos, oid
	end,
	
	---
	-- Decodes length part of encoded value according to ASN.1 basic encoding
	-- rules.
	-- @param encStr Encoded string.
	-- @param pos Current position in the string.
	-- @return The position after decoding.
	-- @return The length of the following value.
	decodeLength = function(encStr, pos)
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
	end,
	
	---
	-- Decodes an Integer according to ASN.1 basic encoding rules.
	-- @param encStr Encoded string.
	-- @param len Length of integer in bytes.
	-- @param pos Current position in the string.
	-- @return The position after decoding.
	-- @return The decoded integer.
	decodeInt = function(encStr, len, pos)
	   local hexStr
	   pos, hexStr = bin.unpack("H" .. len, encStr, pos)
	   local value = tonumber(hexStr, 16)
	   if (value >= math.pow(256, len)/2) then
	      value = value - math.pow(256, len)
	   end
	   return pos, value
	end,
	
	---
	-- Decodes an SNMP packet or a part of it according to ASN.1 basic encoding
	-- rules.
	-- @param encStr Encoded string.
	-- @param pos Current position in the string.
	-- @return The decoded value(s).
	dec = function(self, encStr, pos)
	   local result
	   local _
	   _, result = self:decode(encStr, pos)
	   return result
	end,
	
}

--- The encoder class
--
ASN1Encoder = {

	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o:registerBaseEncoders()
		return o
    end,

	---
	-- Encodes an ASN1 sequence, the value of 30 below breaks down as
	-- 0x30  = 00110000 =  00          1                   10000
	-- hex       binary    Universal   Constructed value   Data Type = SEQUENCE (16)  
	encodeSeq = function(self, seqData)
		return bin.pack('HAA' , '30', self.encodeLength(#seqData), seqData)
	end,

	---
	-- Encodes a given value according to ASN.1 basic encoding rules for SNMP
	-- packet creation.
	-- @param val Value to be encoded.
	-- @return Encoded value.
	encode = function(self, val)
		local vtype = type(val)

		if self.encoder[vtype] then
			return self.encoder[vtype](self,val)
		else
			return nil
		end

		return ''
	end,
	
	--- Allows for registration of additional tag encoders
	--
	-- @param tagEncoders table containing encoding functions @see tagEncoders
	registerTagEncoders = function(self, tagEncoders)
		self:registerBaseEncoders()
		for k, v in pairs(tagEncoders) do
			self.encoder[k] = v
		end
	end,
	
	-- ASN.1 Simple types encoders
	registerBaseEncoders = function(self)
		self.encoder = {}

		-- Bolean encoder
		self.encoder['boolean'] = function( self, val )
			if val then 
	    		return bin.pack('H','01 01 FF')
			else 
	    		return bin.pack('H', '01 01 00')
			end
		end
		
		-- Table encoder
		self.encoder['table'] = function( self, val )
			assert('table' == type(val), "val is not a table")
			assert(#val.type > 0, "Table is missing the type field")
			assert(val.value ~= nil, "Table is missing the value field")
			return bin.pack("HAA", val.type, self.encodeLength(#val.value), val.value)
		end
		
		-- Integer encoder
		self.encoder['number'] = function( self, val )
			local ival = self.encodeInt(val)
	  		local len = self.encodeLength(#ival)
	  		return bin.pack('HAA', '02', len, ival)
		end

		-- Octet String encoder
		self.encoder['string'] = function( self, val )
			local len = self.encodeLength(#val)
			return bin.pack('HAA', '04', len, val)
		end

		-- Null encoder
		self.encoder['nil'] = function( self, val )
			return bin.pack('H', '05 00')
		end
		
	end,
	
	-- Encode one component of an OID as a byte string. 7 bits of the component are
	-- stored in each octet, most significant first, with the eigth bit set in all
	-- octets but the last. These encoding rules come from
	-- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
	-- IDENTIFIER.
	encode_oid_component = function(n)
	  local parts = {}
	  parts[1] = string.char(bit.mod(n, 128))
	  while n >= 128 do
	    n = bit.rshift(n, 7)
	    parts[#parts + 1] = string.char(bit.mod(n, 128) + 0x80)
	  end
	  return string.reverse(table.concat(parts))
	end,

	---
	-- Encodes an Integer according to ASN.1 basic encoding rules.
	-- @param val Value to be encoded.
	-- @return Encoded integer.
	encodeInt = function(val)
	   local lsb = 0
	   if val > 0 then
	      local valStr = ""
	      while (val > 0) do
		 lsb = math.fmod(val, 256)
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
		 lsb = math.fmod(tcval, 256)
		 valStr = valStr .. bin.pack("C", lsb)
		 tcval = math.floor(tcval/256)
	      end
	      return string.reverse(valStr)
	   else -- val == 0
	      return bin.pack("x")
	   end
	end,
	
	---
	-- Encodes the length part of a ASN.1 encoding triplet using the "primitive,
	-- definite-length" method.
	-- @param len Length to be encoded.
	-- @return Encoded length value.
	encodeLength = function(len)
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
}


---
-- Converts a BER encoded type to a numeric value
-- This allows it to be used in the encoding function
--
-- @param class number - see <code>BERCLASS<code>
-- @param constructed boolean (true if constructed, false if primitive)
-- @param number numeric
-- @return number to be used with <code>encode</code>
function BERtoInt(class, constructed, number)

	local asn1_type = class + number

	if constructed == true then
		asn1_type = asn1_type + 32
	end

	return asn1_type
end

---
-- Converts an integer to a BER encoded type table
--
-- @param i number containing the value to decode
-- @return table with the following entries <code>class</code>, <code>constructed</code>, 
-- <code>primitive</code> and <code>number</code>
function intToBER( i )
	local ber = {}

	if bit.band( i, BERCLASS.Application ) == BERCLASS.Application then
		ber.class = BERCLASS.Application
	elseif bit.band( i, BERCLASS.ContextSpecific ) == BERCLASS.ContextSpecific then
		ber.class = BERCLASS.ContextSpecific
	elseif bit.band( i, BERCLASS.Private ) == BERCLASS.Private then
		ber.class = BERCLASS.Private
	else
		ber.class = BERCLASS.Universal
	end
	if bit.band( i, 32 ) == 32 then
		ber.constructed = true
		ber.number = i - ber.class - 32
	else
		ber.primitive = true
		ber.number = i - ber.class 
	end
	return ber
end



return _ENV;
