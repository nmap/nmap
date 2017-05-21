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
-- Base64 encoding and decoding. Follows RFC 4648.
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

_ENV = require "stdnse".module("base64")

local b64table = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
}

---
-- Encodes a string to Base64.
-- @param bdata Data to be encoded.
-- @return Base64-encoded string.
function enc (p)
    local out = {}
    local i = 1
    local m = #p % 3

    while i+2 <= #p do
        local a, b, c = p:byte(i, i+2)
		local e1 = b64table[((a>>2)&0x3f)+1];
		local e2 = b64table[((((a<<4)&0x30)|((b>>4)&0xf))&0x3f)+1];
        local e3 = b64table[((((b<<2)&0x3c)|((c>>6)&0x3))&0x3f)+1];
        local e4 = b64table[(c&0x3f)+1];
        out[#out+1] = e1..e2..e3..e4
        i = i + 3
    end

    if m == 2 then
        local a, b = p:byte(i, i+1)
        local c = 0
		local e1 = b64table[((a>>2)&0x3f)+1];
		local e2 = b64table[((((a<<4)&0x30)|((b>>4)&0xf))&0x3f)+1];
        local e3 = b64table[((((b<<2)&0x3c)|((c>>6)&0x3))&0x3f)+1];
        out[#out+1] = e1..e2..e3.."="
    elseif m == 1 then
        local a = p:byte(i)
        local b = 0
		local e1 = b64table[((a>>2)&0x3f)+1];
		local e2 = b64table[((((a<<4)&0x30)|((b>>4)&0xf))&0x3f)+1];
        out[#out+1] = e1..e2.."=="
    end

    return concat(out)
end

local db64table = setmetatable({}, {__index = function (t, k) error "invalid encoding: invalid character" end})
do
    local r = {["="] = 0}
    for i, v in ipairs(b64table) do
        r[v] = i-1
    end
    for i = 0, 255 do
        db64table[i] = r[char(i)]
    end
end

---
-- Decodes Base64-encoded data.
-- @param b64data Base64 encoded data.
-- @return Decoded data.
function dec (e)
    local out = {}
    local i = 1
    local done = false

    e = e:gsub("%s+", "")

    local m = #e % 4
    if m ~= 0 then
        error "invalid encoding: input is not divisible by 4"
    end

    while i+3 <= #e do
        if done then
            error "invalid encoding: trailing characters"
        end

        local a, b, c, d = e:byte(i, i+3)

        local x = ((db64table[a]<<2)&0xfc) | ((db64table[b]>>4)&0x03)
        local y = ((db64table[b]<<4)&0xf0) | ((db64table[c]>>2)&0x0f)
        local z = ((db64table[c]<<6)&0xc0) | ((db64table[d])&0x3f)

        if c == 0x3d then
            assert(d == 0x3d, "invalid encoding: invalid character")
            out[#out+1] = char(x)
            done = true
        elseif d == 0x3d then
            out[#out+1] = char(x, y)
            done = true
        else
            out[#out+1] = char(x, y, z)
        end
        i = i + 4
    end

    return concat(out)
end

do
    local function test(a, b)
        assert(enc(a) == b and dec(b) == a)
    end
    test("", "")
    test("\x01", "AQ==")
    test("\x00", "AA==")
    test("\x00\x01", "AAE=")
    test("\x00\x01\x02", "AAEC")
    test("\x00\x01\x02\x03", "AAECAw==")
    test("\x00\x01\x02\x03\x04", "AAECAwQ=")
    test("\x00\x01\x02\x03\x04\x05", "AAECAwQF")
    test("\x00\x01\x02\x03\x04\x05\x06", "AAECAwQFBg==")
    test("\x00\x01\x02\x03\x04\x05\x06\x07", "AAECAwQFBgc=")
    for i = 1, 255 do
        test(char(i), enc(char(i)))
    end

    -- whitespace stripping
    assert(dec(" AAEC A\r\nw==") == "\x00\x01\x02\x03")

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
        local good = assert(popen("base64 < "..path, "r")):read("a"):gsub("%s", "")
        remove(path)
        assert(output == good)
        assert(dec(output) == input)
    end
end

return _ENV
