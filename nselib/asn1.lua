---
-- ASN.1 functions.
--
-- Large chunks of this code have been ripped right out from <code>snmp.lua</code>.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @author Patrik Karlsson
-- @class module
-- @name asn1
--

-- Version 0.3
-- Created 01/12/2010 - v0.1 - Created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/28/2010 - v0.2 - Adapted to create a framework for SNMP, LDAP and future protocols
-- Revised 02/02/2010 - v0.3 - Changes: o Re-designed so that ASN1Encoder and ASN1Decoder are separate classes
--                             o Each script or library should now create its own Encoder and Decoder instance
--

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

  --- Tells the decoder to stop if it detects an error while decoding.
  --
  -- This should probably be the default, but some scripts depend on being
  -- able to decode stuff while lacking proper ASN1 decoding functions.
  -- @name ASN1Decoder.setStopOnError
  -- @param val boolean, true if decoding should stop on error,
  --        otherwise false (default)
  setStopOnError = function(self, val)
    self.stoponerror = val
  end,

  --- Registers the base simple type decoders
  -- @name ASN1Decoder.registerBaseDecoders
  registerBaseDecoders = function(self)
    self.decoder = {}

    -- Boolean
    self.decoder["\x01"] = function( self, encStr, elen, pos )
      local val = string.byte(encStr, pos)
      return val ~= 0, pos + 1
    end

    -- Integer
    self.decoder["\x02"] = function( self, encStr, elen, pos )
      return self.decodeInt(encStr, elen, pos)
    end

    -- Octet String
    self.decoder["\x04"] = function( self, encStr, elen, pos )
      return string.unpack("c" .. elen, encStr, pos)
    end

    -- Null
    self.decoder["\x05"] = function( self, encStr, elen, pos )
      return false, pos
    end

    -- Object Identifier
    self.decoder["\x06"] = function( self, encStr, elen, pos )
      return self:decodeOID( encStr, elen, pos )
    end

    -- Context specific tags
    --
    self.decoder["\x30"] = function( self, encStr, elen, pos )
      return self:decodeSeq(encStr, elen, pos)
    end
  end,

  --- Table for registering additional tag decoders.
  --
  -- Each index is a tag number as a hex string. Values are ASN1 decoder
  -- functions.
  -- @name tagDecoders
  -- @class table
  -- @see asn1.decoder

  --- Template for an ASN1 decoder function.
  -- @name asn1.decoder
  -- @class function
  -- @param self The ASN1Decoder object
  -- @param encStr Encoded string
  -- @param elen Length of the object in bytes
  -- @param pos Current position in the string
  -- @return The decoded object
  -- @return The position after decoding

  --- Allows for registration of additional tag decoders
  -- @name ASN1Decoder.registerTagDecoders
  -- @param tagDecoders table containing decoding functions
  -- @see tagDecoders
  registerTagDecoders = function(self, tagDecoders)
    self:registerBaseDecoders()
    for k, v in pairs(tagDecoders) do
      self.decoder[k] = v
    end
  end,

  --- Decodes the ASN.1's built-in simple types
  -- @name ASN1Decoder.decode
  -- @param encStr Encoded string.
  -- @param pos Current position in the string.
  -- @return The decoded value(s).
  -- @return The position after decoding
  decode = function(self, encStr, pos)

    local etype, elen
    local newpos = pos

    etype, newpos = string.unpack("c1", encStr, newpos)
    elen, newpos = self.decodeLength(encStr, newpos)

    if self.decoder[etype] then
      return self.decoder[etype]( self, encStr, elen, newpos )
    else
      stdnse.debug1("no decoder for etype: %s", stdnse.tohex(etype))
      return nil, newpos
    end
  end,

  ---
  -- Decodes length part of encoded value according to ASN.1 basic encoding
  -- rules.
  -- @name ASN1Decoder.decodeLength
  -- @param encStr Encoded string.
  -- @param pos Current position in the string.
  -- @return The length of the following value.
  -- @return The position after decoding.
  decodeLength = function(encStr, pos)
    local elen, newpos = string.unpack('B', encStr, pos)
    if (elen > 128) then
      elen = elen - 128
      local elenCalc = 0
      local elenNext
      for i = 1, elen do
        elenCalc = elenCalc * 256
        elenNext, newpos = string.unpack('B', encStr, newpos)
        elenCalc = elenCalc + elenNext
      end
      elen = elenCalc
    end
    return elen, newpos
  end,

  ---
  -- Decodes a sequence according to ASN.1 basic encoding rules.
  -- @name ASN1Decoder.decodeSeq
  -- @param encStr Encoded string.
  -- @param len Length of sequence in bytes.
  -- @param pos Current position in the string.
  -- @return The decoded sequence as a table.
  -- @return The position after decoding.
  decodeSeq = function(self, encStr, len, pos)
    local seq = {}
    local sPos = 1
    local sStr, newpos = string.unpack("c" .. len, encStr, pos)
    while (sPos < len) do
      local newSeq
      newSeq, sPos = self:decode(sStr, sPos)
      if ( not(newSeq) and self.stoponerror ) then break end
      table.insert(seq, newSeq)
    end
    return seq, newpos
  end,

  -- Decode one component of an OID from a byte string. 7 bits of the component
  -- are stored in each octet, most significant first, with the eighth bit set in
  -- all octets but the last. These encoding rules come from
  -- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
  -- IDENTIFIER.
  decode_oid_component = function(encStr, pos)
    local octet
    local n = 0

    repeat
      octet, pos = string.unpack("B", encStr, pos)
      n = n * 128 + (0x7F & octet)
    until octet < 128

    return n, pos
  end,

  --- Decodes an OID from a sequence of bytes.
  -- @name ASN1Decoder.decodeOID
  -- @param encStr Encoded string.
  -- @param len Length of sequence in bytes.
  -- @param pos Current position in the string.
  -- @return The OID as an array.
  -- @return The position after decoding.
  decodeOID = function(self, encStr, len, pos)
    local last
    local oid = {}
    local octet

    last = pos + len - 1
    if pos <= last then
      oid._snmp = '\x06'
      octet, pos = string.unpack("B", encStr, pos)
      oid[2] = math.fmod(octet, 40)
      octet = octet - oid[2]
      oid[1] = octet//40
    end

    while pos <= last do
      local c
      c, pos = self.decode_oid_component(encStr, pos)
      oid[#oid + 1] = c
    end

    return oid, pos
  end,

  ---
  -- Decodes an Integer according to ASN.1 basic encoding rules.
  -- @name ASN1Decoder.decodeInt
  -- @param encStr Encoded string.
  -- @param len Length of integer in bytes.
  -- @param pos Current position in the string.
  -- @return The decoded integer.
  -- @return The position after decoding.
  decodeInt = function(encStr, len, pos)
    if len > 16 then
      stdnse.debug2("asn1: Unable to decode %d-byte integer at %d", len, pos)
      return nil, pos
    end
    return string.unpack(">i" .. len, encStr, pos)
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
  -- Encodes an ASN1 sequence
  -- @name ASN1Encoder.encodeSeq
  -- @param seqData A string of sequence data
  -- @return ASN.1 BER-encoded sequence
  encodeSeq = function(self, seqData)
    -- 0x30  = 00110000 =  00          1                   10000
    -- hex       binary    Universal   Constructed value   Data Type = SEQUENCE (16)
    return "\x30" .. self.encodeLength(#seqData) .. seqData
  end,

  ---
  -- Encodes a given value according to ASN.1 basic encoding rules for SNMP
  -- packet creation.
  -- @name ASN1Encoder.encode
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

  --- Table for registering additional tag encoders.
  --
  -- Each index is a lua type as a string. Values are ASN1 encoder
  -- functions.
  -- @name tagEncoders
  -- @class table
  -- @see asn1.encoder

  --- Template for an ASN1 encoder function.
  -- @name asn1.encoder
  -- @param self The ASN1Encoder object
  -- @param val The value to encode
  -- @return The encoded object
  -- @class function

  --- Allows for registration of additional tag encoders
  -- @name ASN1Decoder.registerTagEncoders
  -- @param tagEncoders table containing encoding functions
  -- @see tagEncoders
  registerTagEncoders = function(self, tagEncoders)
    self:registerBaseEncoders()
    for k, v in pairs(tagEncoders) do
      self.encoder[k] = v
    end
  end,

  --- Registers the base ASN.1 Simple types encoders
  --
  -- * boolean
  -- * integer (Lua number)
  -- * string
  -- * null (Lua nil)
  -- @name ASN1Encoder.registerBaseEncoders
  registerBaseEncoders = function(self)
    self.encoder = {}

    -- Boolean encoder
    self.encoder['boolean'] = function( self, val )
      if val then
        return '\x01\x01\xFF'
      else
        return '\x01\x01\x00'
      end
    end

    -- Table encoder
    self.encoder['table'] = function( self, val )
      assert('table' == type(val), "val is not a table")
      assert(#val.type > 0, "Table is missing the type field")
      assert(val.value ~= nil, "Table is missing the value field")
      return stdnse.fromhex(val.type) .. self.encodeLength(#val.value) .. val.value
    end

    -- Integer encoder
    self.encoder['number'] = function( self, val )
      local ival = self.encodeInt(val)
      local len = self.encodeLength(#ival)
      return "\x02" .. len .. ival
    end

    -- Octet String encoder
    self.encoder['string'] = function( self, val )
      local len = self.encodeLength(#val)
      return "\x04" .. len .. val
    end

    -- Null encoder
    self.encoder['nil'] = function( self, val )
      return '\x05\x00'
    end

  end,

  -- Encode one component of an OID as a byte string. 7 bits of the component are
  -- stored in each octet, most significant first, with the eighth bit set in all
  -- octets but the last. These encoding rules come from
  -- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
  -- IDENTIFIER.
  encode_oid_component = function(n)
    local parts = {}
    parts[1] = string.char(n % 128)
    while n >= 128 do
      n = n >> 7
      parts[#parts + 1] = string.char(n % 128 + 0x80)
    end
    return string.reverse(table.concat(parts))
  end,

  ---
  -- Encodes an Integer according to ASN.1 basic encoding rules.
  -- @name ASN1Encoder.encodeInt
  -- @param val Value to be encoded.
  -- @return Encoded integer.
  encodeInt = function(val)
    local lsb = 0
    if val > 0 then
      local valStr = ""
      while (val > 0) do
        lsb = math.fmod(val, 256)
        valStr = valStr .. string.pack("B", lsb)
        val = math.floor(val/256)
      end
      if lsb > 127 then -- two's complement collision
        valStr = valStr .. "\0"
      end

      return string.reverse(valStr)
    elseif val < 0 then
      local i = 1
      local tcval = val + 256 -- two's complement
      while tcval <= 127 do
        tcval = tcval + 256^i * 255
        i = i+1
      end
      local valStr = ""
      while (tcval > 0) do
        lsb = math.fmod(tcval, 256)
        valStr = valStr .. string.pack("B", lsb)
        tcval = math.floor(tcval/256)
      end
      return string.reverse(valStr)
    else -- val == 0
      return '\0'
    end
  end,

  ---
  -- Encodes the length part of a ASN.1 encoding triplet using the "primitive,
  -- definite-length" method.
  -- @name ASN1Encoder.encodeLength
  -- @param len Length to be encoded.
  -- @return Encoded length value.
  encodeLength = function(len)
    if len < 128 then
      return string.char(len)
    else
      local parts = {}

      while len > 0 do
        parts[#parts + 1] = string.char(len % 256)
        len = len >> 8
      end

      assert(#parts < 128)
      return string.char(#parts + 0x80) .. string.reverse(table.concat(parts))
    end
  end
}


--- Converts a BER encoded type to a numeric value
--
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
-- @return table with the following entries:
-- * <code>class</code>
-- * <code>constructed</code>
-- * <code>primitive</code>
-- * <code>number</code>
function intToBER( i )
  local ber = {}

  if i & BERCLASS.Application == BERCLASS.Application then
    ber.class = BERCLASS.Application
  elseif i & BERCLASS.ContextSpecific == BERCLASS.ContextSpecific then
    ber.class = BERCLASS.ContextSpecific
  elseif i & BERCLASS.Private == BERCLASS.Private then
    ber.class = BERCLASS.Private
  else
    ber.class = BERCLASS.Universal
  end
  if i & 32 == 32 then
    ber.constructed = true
    ber.number = i - ber.class - 32
  else
    ber.primitive = true
    ber.number = i - ber.class
  end
  return ber
end

local unittest = require 'unittest'
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

do
  local decode_tests = {
    {unittest.is_false, "\x01\x01\x00", nil, "decode false"},
    {unittest.is_true, "\x01\x01\x01", nil, "decode true"},
    {unittest.is_true, "\x01\x01\xff", nil, "decode true (not 1)"},
    {unittest.equal, "\x02\x01\x01", 1, "decode integer"},
    {unittest.equal, "\x02\x02\xff\xff", -1, "decode negative integer"},
    {unittest.equal, "\x02\x03\x01\x00\x02", 65538, "decode integer"},
    {unittest.equal, "\x04\x04nmap", "nmap", "decode octet string"},
    {unittest.is_false, "\x05\x00", nil, "decode null as false"},
    {unittest.identical, "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04\x31",
      {1, 2, 840, 113549, 1, 9, 4, _snmp="\x06"}, "decode OID"
    },
    {unittest.identical, "\x30\x09\x02\x01\x01\x02\x01\xff\x02\x01\x42",
      {1, -1, 0x42}, "decode sequence"
    },
  }
  local test_decoder = ASN1Decoder:new()
  test_decoder:registerBaseDecoders()

  for _, test in ipairs(decode_tests) do
    test_suite:add_test(test[1](test_decoder:decode(test[2], 1), test[3]), test[4])
  end
end

return _ENV;
