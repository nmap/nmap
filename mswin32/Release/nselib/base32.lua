---
-- Base32 encoding and decoding. Follows RFC 4648.
--
-- @author Philip Pickering <pgpickering@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @ported base64 to base32 <john.r.bond@gmail.com>

-- thanks to Patrick Donnelly for some optimizations

--module(... or "base32",package.seeall)
-- local bin = require 'bin'
-- local stdnse = require 'stdnse'
-- _ENV = stdnse.module("base32", stdnse.seeall)

local bin = require "bin"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("base32", stdnse.seeall)

-- todo: make metatable/index --> '' for b32dctable


local b32standard = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', '2', '3', '4', '5', '6', '7',
}

local b32dcstandard = {} -- efficiency
b32dcstandard['A'] = '00000'
b32dcstandard['B'] = '00001'
b32dcstandard['C'] = '00010'
b32dcstandard['D'] = '00011'
b32dcstandard['E'] = '00100'
b32dcstandard['F'] = '00101'
b32dcstandard['G'] = '00110'
b32dcstandard['H'] = '00111'
b32dcstandard['I'] = '01000'
b32dcstandard['J'] = '01001'
b32dcstandard['K'] = '01010'
b32dcstandard['L'] = '01011'
b32dcstandard['M'] = '01100'
b32dcstandard['N'] = '01101'
b32dcstandard['O'] = '01110'
b32dcstandard['P'] = '01111'
b32dcstandard['Q'] = '10000'
b32dcstandard['R'] = '10001'
b32dcstandard['S'] = '10010'
b32dcstandard['T'] = '10011'
b32dcstandard['U'] = '10100'
b32dcstandard['V'] = '10101'
b32dcstandard['W'] = '10110'
b32dcstandard['X'] = '10111'
b32dcstandard['Y'] = '11000'
b32dcstandard['Z'] = '11001'
b32dcstandard['2'] = '11010'
b32dcstandard['3'] = '11011'
b32dcstandard['4'] = '11100'
b32dcstandard['5'] = '11101'
b32dcstandard['6'] = '11110'
b32dcstandard['7'] = '11111'

local b32hexExtend = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
}

local b32dchexExtend = {} -- efficiency
b32dchexExtend['0'] = '00000'
b32dchexExtend['1'] = '00001'
b32dchexExtend['2'] = '00010'
b32dchexExtend['3'] = '00011'
b32dchexExtend['4'] = '00100'
b32dchexExtend['5'] = '00101'
b32dchexExtend['6'] = '00110'
b32dchexExtend['7'] = '00111'
b32dchexExtend['8'] = '01000'
b32dchexExtend['9'] = '01001'
b32dchexExtend['A'] = '01010'
b32dchexExtend['B'] = '01011'
b32dchexExtend['C'] = '01100'
b32dchexExtend['D'] = '01101'
b32dchexExtend['E'] = '01110'
b32dchexExtend['F'] = '01111'
b32dchexExtend['G'] = '10000'
b32dchexExtend['H'] = '10001'
b32dchexExtend['I'] = '10010'
b32dchexExtend['J'] = '10011'
b32dchexExtend['K'] = '10100'
b32dchexExtend['L'] = '10101'
b32dchexExtend['M'] = '10110'
b32dchexExtend['N'] = '10111'
b32dchexExtend['O'] = '11000'
b32dchexExtend['P'] = '11001'
b32dchexExtend['Q'] = '11010'
b32dchexExtend['R'] = '11011'
b32dchexExtend['S'] = '11100'
b32dchexExtend['T'] = '11101'
b32dchexExtend['U'] = '11110'
b32dchexExtend['V'] = '11111'

local b32table = b32standard
local b32dctable = b32dcstandard

local append = table.insert
local substr = string.sub
local bpack = bin.pack
local bunpack = bin.unpack
local concat = table.concat

---
-- Encode bits to a Base32-encoded character.
-- @param bits String of five bits to be encoded.
-- @return Encoded character.
local function b32enc5bit(bits)
  local byte = tonumber(bits, 2) + 1
  return b32table[byte]
end


---
-- Decodes a Base32-encoded character into a string of binary digits.
-- @param b32byte A single base32-encoded character.
-- @return String of five decoded bits.
local function b32dec5bit(b32byte)
  local bits = b32dctable[b32byte]
  if bits then return bits end
  return ''
end


---
-- Encodes a string to Base32.
-- @param bdata Data to be encoded.
-- @param hexExtend pass true to use the hex extended char set
-- @return Base32-encoded string.
function enc(bdata, hexExtend)
  local _, bitstring = bunpack(">B".. #bdata,bdata)
  local b32dataBuf = {}

  if hexExtend then
    b32table = b32hexExtend
    b32dctable = b32dchexExtend
  end

  while #bitstring > 4 do
    append(b32dataBuf,b32enc5bit(substr(bitstring,1,5)))
    bitstring = substr(bitstring,6)
  end
  if #bitstring == 1 then
    append(b32dataBuf, b32enc5bit(bitstring .. "0000"))
    append(b32dataBuf, '====')
  elseif #bitstring == 2 then
    append(b32dataBuf, b32enc5bit(bitstring .. "000") )
    append(b32dataBuf, '=')
  elseif #bitstring == 3 then
    append(b32dataBuf, b32enc5bit(bitstring .. "00") )
    append(b32dataBuf, "======")
  elseif #bitstring == 4 then
    append(b32dataBuf, b32enc5bit(bitstring .. "0") )
    append(b32dataBuf, '===')
  end
  return concat(b32dataBuf)
end


---
-- Decodes Base32-encoded data.
-- @param b32data Base32 encoded data.
-- @param hexExtend pass true to use the hex extended char set
-- @return Decoded data.
function dec(b32data, hexExtend)
  local bdataBuf = {}
  local pos = 1
  local byte
  local nbyte = ''

  if hexExtend then
    b32table = b32hexExtend
    b32dctable = b32dchexExtend
  end

  for pos = 1, #b32data do -- while pos <= string.len(b32data) do
    byte = b32dec5bit(substr(b32data, pos, pos))
    if not byte then return end
    nbyte = nbyte .. byte
    if #nbyte >= 8 then
      append(bdataBuf, bpack("B", substr(nbyte, 1, 8)))
      nbyte = substr(nbyte, 9)
    end
    -- pos = pos + 1
  end
  return concat(bdataBuf)
end

return _ENV;
