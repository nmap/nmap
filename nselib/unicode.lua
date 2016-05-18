---
-- Library methods for handling unicode strings.
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html


local bit = require "bit"
local bin = require "bin"
local string = require "string"
local table = require "table"
local stdnse = require "stdnse"
local unittest = require "unittest"
_ENV = stdnse.module("unicode", stdnse.seeall)

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

---Transcode a string from one format to another
--
--The string will be decoded and re-encoded in one pass. This saves some
--overhead vs simply passing the output of <code>unicode.encode</code> to
--<code>unicode.decode</code>.
--@param buf The string/buffer to be transcoded
--@param decoder A Unicode decoder function (such as utf16_dec)
--@param encoder A Unicode encoder function (such as utf8_enc)
--@param bigendian_dec Set this to true to force big-endian decoding.
--@param bigendian_enc Set this to true to force big-endian encoding.
--@return An encoded string
function transcode(buf, decoder, encoder, bigendian_dec, bigendian_enc)
  local out = {}
  local cp
  local pos = 1
  while pos <= #buf do
    pos, cp = decoder(buf, pos, bigendian_dec)
    out[#out+1] = encoder(cp, bigendian_enc)
  end
  return table.concat(out)
end

---Encode a Unicode code point to UTF-16. See RFC 2781.
--
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
--
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
--
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
--
-- Does not check that the returned code point is a real character.
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@return pos The index in the string where the character ended or nil on error
--@return cp The code point of the character as a number, or an error string
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
    return nil, string.format("Invalid UTF-8 byte at %d", pos)
  end

  local cp = bv - mask

  if pos + n > #buf then
    return nil, string.format("Incomplete UTF-8 sequence at %d", pos)
  end
  for i = 1, n do
    bv = byte(buf, pos + i)
    if bv < 0x80 or bv > 0xBF then
      return nil, string.format("Invalid UTF-8 sequence at %d", pos + i)
    end
    cp = lshift(cp, 6) + band(bv, 0x3F)
  end

  return pos + 1 + n, cp
end

--Invert a one-to-one mapping
local function invert(t)
  local out = {}
  for k, v in pairs(t) do
    out[v] = k
  end
  return out
end

-- Code Page 437, native US-English Windows OEM code page
local cp437_decode = {
  [0x80] = 0x00c7,
  [0x81] = 0x00fc,
  [0x82] = 0x00e9,
  [0x83] = 0x00e2,
  [0x84] = 0x00e4,
  [0x85] = 0x00e0,
  [0x86] = 0x00e5,
  [0x87] = 0x00e7,
  [0x88] = 0x00ea,
  [0x89] = 0x00eb,
  [0x8a] = 0x00e8,
  [0x8b] = 0x00ef,
  [0x8c] = 0x00ee,
  [0x8d] = 0x00ec,
  [0x8e] = 0x00c4,
  [0x8f] = 0x00c5,
  [0x90] = 0x00c9,
  [0x91] = 0x00e6,
  [0x92] = 0x00c6,
  [0x93] = 0x00f4,
  [0x94] = 0x00f6,
  [0x95] = 0x00f2,
  [0x96] = 0x00fb,
  [0x97] = 0x00f9,
  [0x98] = 0x00ff,
  [0x99] = 0x00d6,
  [0x9a] = 0x00dc,
  [0x9b] = 0x00a2,
  [0x9c] = 0x00a3,
  [0x9d] = 0x00a5,
  [0x9e] = 0x20a7,
  [0x9f] = 0x0192,
  [0xa0] = 0x00e1,
  [0xa1] = 0x00ed,
  [0xa2] = 0x00f3,
  [0xa3] = 0x00fa,
  [0xa4] = 0x00f1,
  [0xa5] = 0x00d1,
  [0xa6] = 0x00aa,
  [0xa7] = 0x00ba,
  [0xa8] = 0x00bf,
  [0xa9] = 0x2310,
  [0xaa] = 0x00ac,
  [0xab] = 0x00bd,
  [0xac] = 0x00bc,
  [0xad] = 0x00a1,
  [0xae] = 0x00ab,
  [0xaf] = 0x00bb,
  [0xb0] = 0x2591,
  [0xb1] = 0x2592,
  [0xb2] = 0x2593,
  [0xb3] = 0x2502,
  [0xb4] = 0x2524,
  [0xb5] = 0x2561,
  [0xb6] = 0x2562,
  [0xb7] = 0x2556,
  [0xb8] = 0x2555,
  [0xb9] = 0x2563,
  [0xba] = 0x2551,
  [0xbb] = 0x2557,
  [0xbc] = 0x255d,
  [0xbd] = 0x255c,
  [0xbe] = 0x255b,
  [0xbf] = 0x2510,
  [0xc0] = 0x2514,
  [0xc1] = 0x2534,
  [0xc2] = 0x252c,
  [0xc3] = 0x251c,
  [0xc4] = 0x2500,
  [0xc5] = 0x253c,
  [0xc6] = 0x255e,
  [0xc7] = 0x255f,
  [0xc8] = 0x255a,
  [0xc9] = 0x2554,
  [0xca] = 0x2569,
  [0xcb] = 0x2566,
  [0xcc] = 0x2560,
  [0xcd] = 0x2550,
  [0xce] = 0x256c,
  [0xcf] = 0x2567,
  [0xd0] = 0x2568,
  [0xd1] = 0x2564,
  [0xd2] = 0x2565,
  [0xd3] = 0x2559,
  [0xd4] = 0x2558,
  [0xd5] = 0x2552,
  [0xd6] = 0x2553,
  [0xd7] = 0x256b,
  [0xd8] = 0x256a,
  [0xd9] = 0x2518,
  [0xda] = 0x250c,
  [0xdb] = 0x2588,
  [0xdc] = 0x2584,
  [0xdd] = 0x258c,
  [0xde] = 0x2590,
  [0xdf] = 0x2580,
  [0xe0] = 0x03b1,
  [0xe1] = 0x00df,
  [0xe2] = 0x0393,
  [0xe3] = 0x03c0,
  [0xe4] = 0x03a3,
  [0xe5] = 0x03c3,
  [0xe6] = 0x00b5,
  [0xe7] = 0x03c4,
  [0xe8] = 0x03a6,
  [0xe9] = 0x0398,
  [0xea] = 0x03a9,
  [0xeb] = 0x03b4,
  [0xec] = 0x221e,
  [0xed] = 0x03c6,
  [0xee] = 0x03b5,
  [0xef] = 0x2229,
  [0xf0] = 0x2261,
  [0xf1] = 0x00b1,
  [0xf2] = 0x2265,
  [0xf3] = 0x2264,
  [0xf4] = 0x2320,
  [0xf5] = 0x2321,
  [0xf6] = 0x00f7,
  [0xf7] = 0x2248,
  [0xf8] = 0x00b0,
  [0xf9] = 0x2219,
  [0xfa] = 0x00b7,
  [0xfb] = 0x221a,
  [0xfc] = 0x207f,
  [0xfd] = 0x00b2,
  [0xfe] = 0x25a0,
  [0xff] = 0x00a0,
}
local cp437_encode = invert(cp437_decode)

---Encode a Unicode code point to CP437
--
-- Returns nil if the code point cannot be found in CP437
--@param cp The Unicode code point as a number
--@return A string containing the related CP437 character
function cp437_enc(cp)
  if cp < 0x80 then
    return char(cp)
  else
    local bv = cp437_encode[cp]
    if bv == nil then
      return nil
    else
      return char(bv)
    end
  end
end

---Decodes a CP437 character
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@return pos The index in the string where the character ended
--@return cp The code point of the character as a number
function cp437_dec(buf, pos)
  pos = pos or 1
  local bv = byte(buf, pos)
  if bv < 0x80 then
    return pos + 1, bv
  else
    return pos + 1, cp437_decode[bv]
  end
end

---Helper function for the common case of UTF-16 to UTF-8 transcoding, such as
--from a Windows/SMB unicode string to a printable ASCII (subset of UTF-8)
--string.
--@param from A string in UTF-16, little-endian
--@return The string in UTF-8
function utf16to8(from)
  return transcode(from, utf16_dec, utf8_enc, false, nil)
end

---Helper function for the common case of UTF-8 to UTF-16 transcoding, such as
--from a printable ASCII (subset of UTF-8) string to a Windows/SMB unicode
--string.
--@param from A string in UTF-8
--@return The string in UTF-16, little-endian
function utf8to16(from)
  return transcode(from, utf8_dec, utf16_enc, nil, false)
end

if not unittest.testing() then
  return _ENV
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
test_suite:add_test(unittest.equal(utf16to8("\x08\xD8\x45\xDF=\0R\0a\0"), "\xF0\x92\x8D\x85=Ra"),"utf16to8")
test_suite:add_test(unittest.equal(utf8to16("\xF0\x92\x8D\x85=Ra"), "\x08\xD8\x45\xDF=\0R\0a\0"),"utf8to16")
test_suite:add_test(unittest.equal(encode({0x221e, 0x2248, 0x30}, cp437_enc), "\xec\xf70"), "encode cp437")
test_suite:add_test(unittest.table_equal(decode("\x81ber", cp437_dec), {0xfc, 0x62, 0x65, 0x72}), "decode cp437")

return _ENV
