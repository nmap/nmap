---
-- Base64 encoding and decoding. Follows RFC 4648.
--
-- @author Philip Pickering <pgpickering@gmail.com>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- thanks to Patrick Donnelly for some optimizations

local bin = require "bin"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("base64", stdnse.seeall)

-- todo: make metatable/index --> '' for b64dctable


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
	
local b64dctable = {} -- efficency
b64dctable['A'] = '000000'
b64dctable['B'] = '000001'
b64dctable['C'] = '000010'
b64dctable['D'] = '000011'
b64dctable['E'] = '000100'
b64dctable['F'] = '000101'
b64dctable['G'] = '000110'
b64dctable['H'] = '000111'
b64dctable['I'] = '001000'
b64dctable['J'] = '001001'
b64dctable['K'] = '001010'
b64dctable['L'] = '001011'
b64dctable['M'] = '001100'
b64dctable['N'] = '001101'
b64dctable['O'] = '001110'
b64dctable['P'] = '001111'
b64dctable['Q'] = '010000'
b64dctable['R'] = '010001'
b64dctable['S'] = '010010'
b64dctable['T'] = '010011'
b64dctable['U'] = '010100'
b64dctable['V'] = '010101'
b64dctable['W'] = '010110'
b64dctable['X'] = '010111'
b64dctable['Y'] = '011000'
b64dctable['Z'] = '011001'
b64dctable['a'] = '011010'
b64dctable['b'] = '011011'
b64dctable['c'] = '011100'
b64dctable['d'] = '011101'
b64dctable['e'] = '011110'
b64dctable['f'] = '011111'
b64dctable['g'] = '100000'
b64dctable['h'] = '100001'
b64dctable['i'] = '100010'
b64dctable['j'] = '100011'
b64dctable['k'] = '100100'
b64dctable['l'] = '100101'
b64dctable['m'] = '100110'
b64dctable['n'] = '100111'
b64dctable['o'] = '101000'
b64dctable['p'] = '101001'
b64dctable['q'] = '101010'
b64dctable['r'] = '101011'
b64dctable['s'] = '101100'
b64dctable['t'] = '101101'
b64dctable['u'] = '101110'
b64dctable['v'] = '101111'
b64dctable['w'] = '110000'
b64dctable['x'] = '110001'
b64dctable['y'] = '110010'
b64dctable['z'] = '110011'
b64dctable['0'] = '110100'
b64dctable['1'] = '110101'
b64dctable['2'] = '110110'
b64dctable['3'] = '110111'
b64dctable['4'] = '111000'
b64dctable['5'] = '111001'
b64dctable['6'] = '111010'
b64dctable['7'] = '111011'
b64dctable['8'] = '111100'
b64dctable['9'] = '111101'
b64dctable['+'] = '111110'
b64dctable['/'] = '111111'


local append = table.insert
local substr = string.sub
local bpack = bin.pack 
local bunpack = bin.unpack
local concat = table.concat

---
-- Encode six bits to a Base64-encoded character.
-- @param bits String of six bits to be encoded.
-- @return Encoded character.
local function b64enc6bit(bits)
	-- local byte
	-- local _, byte = bunpack("C", bpack("B", "00" .. bits))
	--
	
	-- more efficient, does the same (nb: add one to byte moved up one line):
	local byte = tonumber(bits, 2) + 1
	return b64table[byte]
end


---
-- Decodes a Base64-encoded character into a string of binary digits.
-- @param b64byte A single base64-encoded character.
-- @return String of six decoded bits.
local function b64dec6bit(b64byte)
	local bits = b64dctable[b64byte]
	if bits then return bits end
	return ''
end


---
-- Encodes a string to Base64.
-- @param bdata Data to be encoded.
-- @return Base64-encoded string.
function enc(bdata)
	local pos = 1
	local byte
	local nbyte = ''
	-- local nbuffer = {}
	local b64dataBuf = {}
	while pos <= #bdata  do
		pos, byte = bunpack("B1", bdata, pos)
		nbyte = nbyte .. byte
		append(b64dataBuf, b64enc6bit(substr(nbyte, 1, 6)))
		nbyte = substr(nbyte,7)
		if (#nbyte == 6) then
			append(b64dataBuf, b64enc6bit(nbyte))
			nbyte = ''
		end
	end
	if #nbyte == 2 then
		append(b64dataBuf, b64enc6bit(nbyte .. "0000") ) 
		append(b64dataBuf, "==")
	elseif #nbyte == 4 then
		append(b64dataBuf, b64enc6bit(nbyte .. "00"))
		append(b64dataBuf, '=')
	end
	return concat(b64dataBuf)
end


---
-- Decodes Base64-encoded data.
-- @param b64data Base64 encoded data.
-- @return Decoded data.
function dec(b64data)
	local bdataBuf = {}
	local pos = 1
	local byte
	local nbyte = ''
	for pos = 1, #b64data do -- while pos <= #b64data do
		byte = b64dec6bit(substr(b64data, pos, pos))
		if not byte then return end
		nbyte = nbyte .. byte
		if #nbyte >= 8 then
			append(bdataBuf, bpack("B", substr(nbyte, 1, 8)))
			nbyte = substr(nbyte, 9)
		end
--		pos = pos + 1
	end
	return concat(bdataBuf)
end


return _ENV;
