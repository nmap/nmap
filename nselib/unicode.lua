---
-- Library methods for handling unicode strings.
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html


local bit = require "bit"
local bin = require "bin"
local string = require "string"
local table = require "table"
local stdnse = require "stdnse"
local unittest = require "unittest"
_ENV = stdnse.module("json", stdnse.seeall)

-- Localize a few functions for a tiny speed boost, since these will be looped
-- over every char of a string
local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift
local byte = string.byte
local char = string.char
local pack = bin.pack
local unpack = bin.unpack


---Decode a buffer containing Unicode data.
--@param buf The string/buffer to be decoded
--@param decoder A Unicode decoder function (such as utf8_dec)
--@param bigendian For encodings that care about byte-order (such as UTF-16),
--                 set this to true to force big-endian byte order. Default:
--                 false (little-endian)
--@return A list-table containing the code points as numbers
function decode(buf, decoder, bigendian)
  local cp = {}
  local pos = 1
  while pos <= #buf do
    pos, cp[#cp+1] = decoder(buf, pos, bigendian)
  end
  return cp
end

---Encode a list of Unicode code points
--@param list A list-table of code points as numbers
--@param encoder A Unicode encoder function (such as utf8_enc)
--@param bigendian For encodings that care about byte-order (such as UTF-16),
--                 set this to true to force big-endian byte order. Default:
--                 false (little-endian)
--@return An encoded string
function encode(list, encoder, bigendian)
  local buf = {}
  for i, cp in ipairs(list) do
    buf[i] = encoder(cp, bigendian)
  end
  return table.concat(buf, "")
end

---Encode a Unicode code point to UTF-16. See RFC 2781.
-- Windows OS prior to Windows 2000 only supports UCS-2, so beware using this
-- function to encode code points above 0xFFFF.
--@param cp The Unicode code point as a number
--@param bigendian Set this to true to encode big-endian UTF-16. Default is
--                 false (little-endian)
--@return A string containing the code point in UTF-16 encoding.
function utf16_enc(cp, bigendian)
  local fmt = "<S"
  if bigendian then
    fmt = ">S"
  end

  if cp % 1.0 ~= 0.0 or cp < 0 then
    -- Only defined for nonnegative integers.
    return nil
  elseif cp <= 0xFFFF then
    return pack(fmt, cp)
  elseif cp <= 0x10FFFF then
    cp = cp - 0x10000
    return pack(fmt .. fmt, 0xD800 + rshift(cp, 10), 0xDC00 + band(cp, 0x3FF))
  else
    return nil
  end
end

---Decodes a UTF-16 character.
-- Does not check that the returned code point is a real character.
-- Specifically, it can be fooled by out-of-order lead- and trail-surrogate
-- characters.
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@param bigendian Set this to true to encode big-endian UTF-16. Default is
--                 false (little-endian)
--@return pos The index in the string where the character ended
--@return cp The code point of the character as a number
function utf16_dec(buf, pos, bigendian)
  local fmt = "<S"
  if bigendian then
    fmt = ">S"
  end

  local cp
  pos, cp = unpack(fmt, buf, pos)
  if cp >= 0xD800 and cp <= 0xDFFF then
    local high = lshift(cp - 0xD800, 10)
    pos, cp = unpack(fmt, buf, pos)
    cp = 0x10000 + high + cp - 0xDC00
  end
  return pos, cp
end

---Encode a Unicode code point to UTF-8. See RFC 3629.
-- Does not check that cp is a real character; that is, doesn't exclude the
-- surrogate range U+D800 - U+DFFF and a handful of others.
--@param cp The Unicode code point as a number
--@return A string containing the code point in UTF-8 encoding.
function utf8_enc(cp)
  local bytes = {}
  local n, mask

  if cp % 1.0 ~= 0.0 or cp < 0 then
    -- Only defined for nonnegative integers.
    return nil
  elseif cp <= 0x7F then
    -- Special case of one-byte encoding.
    return char(cp)
  elseif cp <= 0x7FF then
    n = 2
    mask = 0xC0
  elseif cp <= 0xFFFF then
    n = 3
    mask = 0xE0
  elseif cp <= 0x10FFFF then
    n = 4
    mask = 0xF0
  else
    return nil
  end

  while n > 1 do
    bytes[n] = char(0x80 + band(cp, 0x3F))
    cp = rshift(cp, 6)
    n = n - 1
  end
  bytes[1] = char(mask + cp)

  return table.concat(bytes)
end

---Decodes a UTF-8 character.
-- Does not check that the returned code point is a real character.
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@return pos The index in the string where the character ended
--@return cp The code point of the character as a number
function utf8_dec(buf, pos)
  pos = pos or 1
  local n, mask
  local bv = byte(buf, pos)
  if bv <= 0x7F then
    return pos+1, bv
  elseif bv <= 0xDF then
    --110xxxxx 10xxxxxx
    n = 1
    mask = 0xC0
  elseif bv <= 0xEF then
    --1110xxxx 10xxxxxx 10xxxxxx
    n = 2
    mask = 0xE0
  elseif bv <= 0xF7 then
    --11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
    n = 3
    mask = 0xF0
  else
    return nil
  end

  local cp = bv - mask

  for i = 1, n do
    bv = band(byte(buf, pos + i), 0x3F)
    cp = lshift(cp, 6) + bv
  end

  return pos + 1 + n, cp
end

test_suite = unittest.TestSuite:new()
test_suite:add_test(function()
    local pos, cp = utf8_dec("\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E")
    return pos == 4 and cp == 0x65E5, string.format("Expected 4, 0x65E5; got %d, 0x%x", pos, cp)
  end, "utf8_dec")

test_suite:add_test(unittest.equal(encode({0x65E5,0x672C,0x8A9E}, utf8_enc), "\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E"),"encode utf-8")
test_suite:add_test(unittest.equal(encode({0x12345,61,82,97}, utf16_enc), "\x08\xD8\x45\xDF=\0R\0a\0"),"encode utf-16")
test_suite:add_test(unittest.equal(encode({0x12345,61,82,97}, utf16_enc, true), "\xD8\x08\xDF\x45\0=\0R\0a"),"encode utf-16, big-endian")
test_suite:add_test(unittest.table_equal(decode("\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E", utf8_dec), {0x65E5,0x672C,0x8A9E}),"decode utf-8")
test_suite:add_test(unittest.table_equal(decode("\x08\xD8\x45\xDF=\0R\0a\0", utf16_dec), {0x12345,61,82,97}),"decode utf-16")
test_suite:add_test(unittest.table_equal(decode("\xD8\x08\xDF\x45\0=\0R\0a", utf16_dec, true), {0x12345,61,82,97}),"decode utf-16, big-endian")

return _ENV
