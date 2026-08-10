-- The MIT License (MIT)
-- Copyright (c) 2016 Patrick Joseph Donnelly (batrick@batbytes.com)
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

---
-- Base32 encoding and decoding. Follows RFC 4648.
--
-- @author Patrick Donnelly <batrick@batbytes.com>
-- @copyright The MIT License (MIT); Copyright (c) 2016 Patrick Joseph Donnelly (batrick@batbytes.com)

local assert = assert
local error = error
local ipairs = ipairs
local setmetatable = setmetatable

local open = require "io".open
local popen = require "io".popen

local random = require "math".random

local tmpname = require "os".tmpname
local remove = require "os".remove

local char = require "string".char

local concat = require "table".concat

local unittest = require "unittest"

_ENV = require "stdnse".module "base32"

local b32standard = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', '2', '3', '4', '5', '6', '7',
}

local b32hexExtend = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
  'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
  'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
}

local function etransform (t, a, b, c, d, e)
    local e1 = t[((a>>3)&0x1f)+1]
    local e2 = t[((((a<<2)&0x1c)|((b>>6)&0x03))&0x1f)+1]
    local e3 = t[((b>>1)&0x1f)+1]
    local e4 = t[((((b<<4)&0x10)|((c>>4)&0x0f))&0x1f)+1]
    local e5 = t[((((c<<1)&0x1e)|((d>>7)&0x01))&0x1f)+1]
    local e6 = t[((d>>2)&0x1f)+1]
    local e7 = t[((((d<<3)&0x18)|((e>>5)&0x07))&0x1f)+1]
    local e8 = t[(e&0x1f)+1]
	return e1..e2..e3..e4..e5..e6..e7..e8
end

---
-- Encodes a string to Base32.
-- @param p Data to be encoded.
-- @param hexExtend pass true to use the hex extended char set
-- @return Base32-encoded string.
function enc (p, hexExtend)
    local b32table = not hexExtend and b32standard or b32hexExtend

    local out = {}
    local i = 1
    local m = #p % 5

    while i+(5-1) <= #p do
        local a, b, c, d, e = p:byte(i, i+(5-1))
        out[#out+1] = etransform(b32table, a, b, c, d, e)
        i = i + 5
    end

	if m == 4 then
        local a, b, c, d = p:byte(i, i+(4-1))
        out[#out+1] = etransform(b32table, a, b, c, d, 0):sub(1, 7).."="
	elseif m == 3 then
        local a, b, c = p:byte(i, i+(3-1))
        out[#out+1] = etransform(b32table, a, b, c, 0, 0):sub(1, 5).."==="
	elseif m == 2 then
        local a, b = p:byte(i, i+(2-1))
        out[#out+1] = etransform(b32table, a, b, 0, 0, 0):sub(1, 4).."===="
	elseif m == 1 then
        local a = p:byte(i, i+(1-1))
        out[#out+1] = etransform(b32table, a, 0, 0, 0, 0):sub(1, 2).."======"
	end

    return concat(out)
end


local db32metatable = {
  __index = function (t, k) error "invalid encoding: invalid character" end
}
local db32table_standard = setmetatable({}, db32metatable)
do
    local r = {["="] = 0}
    for i, v in ipairs(b32standard) do
        r[v] = i-1
    end
    for i = 0, 255 do
        db32table_standard[i] = r[char(i)]
    end
end
local db32table_hex = setmetatable({}, db32metatable)
do
    local r = {["="] = 0}
    for i, v in ipairs(b32hexExtend) do
        r[v] = i-1
    end
    for i = 0, 255 do
        db32table_hex[i] = r[char(i)]
    end
end


-- Decodes Base32-encoded data.
-- @param b32 Base32 encoded data.
-- @param hexExtend pass true to use the hex extended char set
-- @return Decoded data.
function dec (b32, hexExtend)
    local db32table = not hexExtend and db32table_standard or db32table_hex

    local out = {}
    local i = 1
    local m = #b32 % 8
    local done = false

    if m ~= 0 then
        error "invalid encoding: input is not divisible by 8"
    end

    while i+(8-1) <= #b32 do
        if done then
            error "invalid encoding: trailing characters"
        end

        local a, b, c, d, e, f, g, h = b32:byte(i, i+(8-1))

        local v = ((db32table[a]<<3)&0xf8) | ((db32table[b]>>2)&0x07)
        local w = ((db32table[b]<<6)&0xc0) | ((db32table[c]<<1)&0x3e) | ((db32table[d]>>4)&0x01)
        local x = ((db32table[d]<<4)&0xf0) | ((db32table[e]>>1)&0x0f)
        local y = ((db32table[e]<<7)&0x80) | ((db32table[f]<<2)&0x7c) | ((db32table[g]>>3)&0x03)
        local z = ((db32table[g]<<5)&0xe0) | ((db32table[h]   )&0x1f)

        if c == 0x3d then
            assert(d == 0x3d and e == 0x3d and f == 0x3d and g == 0x3d and h == 0x3d, "invalid encoding: invalid character")
            out[#out+1] = char(v)
            done = true
		elseif d == 0x3d then
            error "invalid encoding: invalid character"
        elseif e == 0x3d then
            assert(f == 0x3d and g == 0x3d and h == 0x3d, "invalid encoding: invalid character")
            out[#out+1] = char(v, w)
            done = true
        elseif f == 0x3d then
            assert(g == 0x3d and h == 0x3d, "invalid encoding: invalid character")
            out[#out+1] = char(v, w, x)
            done = true
        elseif g == 0x3d then
            error "invalid encoding: invalid character"
        elseif h == 0x3d then
            out[#out+1] = char(v, w, x, y)
            done = true
        else
            out[#out+1] = char(v, w, x, y, z)
        end
        i = i + 8
    end

    return concat(out)
end

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

local equal = unittest.equal
local function test(a, b)
  test_suite:add_test(equal(enc(a), b), "encoding")
  test_suite:add_test(equal(dec(b), a), "decoding")
end
local function testh(a, b)
  test_suite:add_test(equal(enc(a, true), b), "hex encoding")
  test_suite:add_test(equal(dec(b, true), a), "hex decoding")
end

test("", "")
test("f", "MY======")
test("fo", "MZXQ====")
test("foo", "MZXW6===")
test("foob", "MZXW6YQ=")
test("fooba", "MZXW6YTB")
test("foobar", "MZXW6YTBOI======")
testh("", "")
testh("f", "CO======")
testh("fo", "CPNG====")
testh("foo", "CPNMU===")
testh("foob", "CPNMUOG=")
testh("foobar", "CPNMUOJ1E8======")

-- extensive tests
if false then
  local path = tmpname()
  local file = open(path, "w")
  local t = {}
  for a = 0, 255, random(1, 7) do
    for b = 0, 255, random(2, 7) do
      for c = 0, 255, random(2, 7) do
        t[#t+1] = char(a, b, c, 0xA)
        file:write(t[#t])
      end
    end
  end
  assert(file:close())
  local input = concat(t)
  local output = enc(input)
  local good = assert(popen("base32 < "..path, "r")):read("a"):gsub("%s", "")
  remove(path)
  assert(output == good)
  assert(dec(output) == input)
end

return _ENV
