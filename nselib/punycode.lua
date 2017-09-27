---
-- Library methods for handling punycode strings.
--
-- Punycode is a simple and efficient transfer encoding syntax designed
-- for use with Internationalized Domain Names in Applications (IDNA).
-- It uniquely and reversibly transforms a Unicode string into an ASCII
-- string.  ASCII characters in the Unicode string are represented
-- literally, and non-ASCII characters are represented by ASCII
-- characters that are allowed in host name labels (letters, digits, and
-- hyphens).  This document defines a general algorithm called
-- Bootstring that allows a string of basic code points to uniquely
-- represent any string of code points drawn from a larger set.
-- Punycode is an instance of Bootstring that uses particular parameter
-- values specified by this document, appropriate for IDNA.
--
-- Advantages of Bootstring algorithm are Completeness, Uniqueness,
-- Reversibility, Efficient encoding, Simplicity and Readability.
--
-- References:
-- * http://ietf.org/rfc/rfc3492.txt
--
-- @author Rewanth Cool
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local stdnse = require "stdnse"
local string = require "string"
local math = require "math"
local table = require "table"
local unicode = require "unicode"
local unittest = require "unittest"

_ENV = stdnse.module("punycode", stdnse.seeall)

-- Localize few functions for a tiny speed boost, since these will be
-- used frequently.
local floor = math.floor
local byte = string.byte
local char = string.char
local find = string.find
local match = string.match
local reverse = string.reverse
local sub = string.sub

-- Highest positive signed 32-bit float value
local maxInt = 0x7FFFFFFF

-- Regular expressions (RFC 3490 separators)
local regexSeparators = {
  0x3002, -- Ideographic full stop
  0xFF0E, -- Fullwidth full stop
  0xFF61 -- Halfwidth ideographic full stop
}

-- Bootstring parameters
local base = 0x24
local tMin = 0x1
local tMax = 0x1A
local skew = 0x26
local damp = 0x2BC
local initialBias = 0x48
local initialN = 0x80
local delimiter = char("0x2D")

-- Convenience shortcuts
local baseMinusTMin = base - tMin

-- This function finds and replaces matched values in a table.
--
-- @param tbl Table of values.
-- @param val Value to to be replaced in the table.
-- @param new_val Value to be replaced with.
-- @return Returns a new table with new values.
local function find_and_replace(tbl, val, new_val)

  for index, data in pairs(tbl) do
      if data == val then
        tbl[index] = new_val
      end
  end

  return tbl

end


-- Bias adaptation function as per section 3.4 of RFC 3492.
-- https://tools.ietf.org/html/rfc3492#section-3.4
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
local function adapt(delta, numPoints, firstTime)

  local k = 0;

  if firstTime then
    delta = floor(delta / damp)
  else
    delta = (delta >> 1)
  end

  delta = delta + floor(delta / numPoints)

  while delta > (baseMinusTMin * tMax >> 1) do
    delta = floor(delta / baseMinusTMin)
    k = k + base
  end

  return floor(k + (baseMinusTMin + 1) * delta / (delta + skew))

end

-- The following function converts boolean value to integer.
--
-- @param status boolean value is given as input.
-- @return Returns 0/1 based on the given boolean input.
local function boolToNum(status)

  if status == true then
    return 1
  else
    return 0
  end

end

-- This function converts a basic code point into a digit/integer.
--
-- @param codePoint The basic numeric code point value.
-- @return The numeric value of a basic code point (for use in
-- representing integers) in the range `0` to `base - 1`, or `base` if
-- the code point does not represent a value.
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
local function basicToDigit(codePoint)

  if (codePoint - 0x30 < 0x0A) then
    return codePoint - 0x16
  end
  if (codePoint - 0x41 < 0x1A) then
    return codePoint - 0x41
  end
  if (codePoint - 0x61 < 0x1A) then
    return codePoint - 0x61
  end

  return base

end


-- This function converts a digit/integer into a basic code point.
--
-- @param digit The numeric value of a basic code point.
-- @return The basic code point whose value (when used for
-- representing integers) is `digit`, which needs to be in the range
-- `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
-- used; else, the lowercase form is used. The behavior is undefined
-- if `flag` is non-zero and `digit` has no uppercase form.
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
local function digitToBasic(digit, flag)
  --  0..25 map to ASCII a..z or A..Z
  -- 26..35 map to ASCII 0..9
  return digit + 22 + 75 * boolToNum(digit < 26) - (boolToNum((flag ~= 0)) << 5)
end

-- This function creates a string based on an array of numeric code points.
--
-- @param input String of input to be encoded.
-- @param decoder Sets the decoding format to be used.
-- @return The new encoded string
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
function encode_input(input, decoder)

  local output = {}

  -- Convert the input into an array of Unicode code points.
  input = unicode.decode(input, decoder)

  -- Cache the length.
  local inputLength = #input

  -- Initialize the state.
  local n = initialN
  local delta = 0
  local bias = initialBias

  -- Handle the basic code points.
  for _, v in ipairs(input) do
    if v < 0x80 then
      table.insert(output, char(v))
    end
  end

  local basicLength = #output
  local handledCPCount = basicLength

  -- `handledCPCount` is the number of code points that have been handled
  -- `basicLength` is the number of basic code points.
  -- Finish the basic string with a delimiter unless it's empty.
  if (basicLength > 0) then
      table.insert(output, delimiter)
  end

  -- Main encoding loop:
  while (handledCPCount < inputLength) do
    -- All non-basic code points < n have been handled already. Find
    -- the next larger one:
    local m = maxInt
    for _, v in ipairs(input) do
      if v >= n and v < m then
        m = v
      end
    end

    -- Increase `delta` enough to advance the decoder's <n,i> state to
    -- <m,0>, but guard against overflow.
    local handledCPCountPlusOne = handledCPCount + 1
    if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) then
      --error('overflow')
      return nil, "Overflow exception occurred."
    end

    delta = delta + (m - n) * handledCPCountPlusOne
    n = m

    for _, currentValue in ipairs(input) do

      if currentValue < n then
        delta = delta + 1 --Move this down incase of wrong answer
        if delta > maxInt then
          --error("overflow")
          return nil, "Overflow exception occurred."
        end
      end

      if (currentValue == n) then
        -- Represent delta as a generalized variable-length integer.
        local q = delta
        local k = base

        repeat
          local t

          if k <= bias then
            t = tMin
          else
            if k >= bias + tMax then
              t = tMax
            else
              t = k - bias
            end
          end

          if q < t then
            break
          end

          local qMinusT = q - t
          local baseMinusT = base - t
          local ans = digitToBasic(t + qMinusT % baseMinusT, 0)

          table.insert(output, char(ans))

          q = floor(qMinusT / baseMinusT)

          k = k + base
        until false

        local ans = digitToBasic(q, 0)
        table.insert(output, char(ans))
        bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength)

        delta = 0
        handledCPCount = handledCPCount + 1
      end
    end

    delta = delta + 1
    n = n + 1

  end

  return table.concat(output, '')

end

-- This function converts a Punycode string of ASCII-only symbols to a
-- string of Unicode symbols.
--
-- @param input The Punycode string of ASCII-only symbols.
-- @param encoder Defines the type of encoding format to be used.
-- @return The resulting string of Unicode symbols.
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
function decode_input(input, encoder)

  local output = {}
  local inputLength = #input
  local i = 0
  local n = initialN
  local bias = initialBias

  local basic
  if find(reverse(input), delimiter) then
    basic = #input - find(reverse(input), delimiter)
  else
    basic = -1
  end

  if basic < 0 then
    basic = 0
  end

  for j = 1, basic do
    local c = sub(input, j, j)
    local value = byte(c)

    if value >= 0x80 then
      --error("Not basic")
      return nil, "Not basic exception occurred."
    end
    table.insert(output, value)
  end

  local index
  if basic > 0 then
    index = basic + 1
  else
    index = 0
  end

  while index < inputLength do
    local oldi = i
    local w = 1
    local k = base

    repeat

      if index >= inputLength then
        --error("Invalid input")
        return nil, "Invalid input exception occurred."
      end

      local c = sub(input, index+1, index+1)
      local value = byte(c)
      local digit = basicToDigit(value)

      index = index + 1

      if (digit >= base or digit > floor((maxInt - i) / w)) then
        --error('overflow');
        return nil, "Overflow exception occurred."
      end
      i = i + digit * w;

      local t
      if k <= bias then
        t = tMin
      else
        if k >= bias + tMax then
          t = tMax
        else
          t = k - bias
        end
      end

      if digit < t then
        break
      end

      local baseMinusT = base - t;
      if (w > floor(maxInt / baseMinusT)) then
        --error('overflow');
        return nil, "Overflow exception occurred."
      end

      w = w * baseMinusT;
      k = k + base

    until false

    local out = #output + 1;

    bias = adapt(i - oldi, out, oldi == 0)

    -- `i` was supposed to wrap around from `out` to `0`,
    -- incrementing `n` each time, so we'll fix that now:
    if (floor(i / out) > maxInt - n) then
      --error('overflow');
      return nil, "Overflow exception occurred."
    end

    n = n + floor(i / out);
    i = i % out;
    for temp = #output, i, -1 do
      output[temp+1] = output[temp]
    end
    output[i+1] = n
    i = i + 1
  end

  return unicode.encode(output, encoder)

end

-- The following function looks for non-ASCII characters in a string.
--
-- @param s String of input to be encoded.
-- @param decoder A decoder function to convert the domain into a
-- table of Unicode code points.
-- @return Returns encoded string.
function encode_label(s, decoder)

  local flag = false
  local decoded_tbl = unicode.decode(s, decoder)

  -- Looks for non-ASCII character
  for _, val in pairs(decoded_tbl) do

    if not (val >=0 and val <= 127) then
      flag = true
      break
    end

  end

  if flag then

    local res, err = encode_input(s, decoder)
    if err then
      return nil, err
    end

    return 'xn--' .. res

  else
    return s
  end

end

-- The following function validates and decodes the given input.
--
-- @param s String of input
-- @param encoder An encoder function to convert a Unicode code point
--        into a string of bytes. Default: unicode.utf8_enc
-- @return Returns decoded string.
function decode_label(s, encoder)

  if match(s, "^xn%-%-") then

    local res, err = decode_input(sub(s, 5):lower(), encoder)
    if err then
      return nil, err
    end

    return res

  else
    return s
  end

end

-- The following function splits the domain name and maps it with the
-- corresponding data.
--
-- @param s The domain name to be processed.
-- @param fn The function to be called for every label.
-- @param formatter The type of encoder/decoder to be used.
-- @param delimiter delimiter character for concatinating output.
-- @return Returns encoded/decoded string based on the formatter.
-- The following function is adapted from punycode.js by Mathias Bynens
-- under the MIT License.
function mapLabels(labels, fn, formatter, delimiter)

  local encoded = {}

  for index, v in ipairs(labels) do

    local res, err = fn(labels[index], formatter)

    if err then
      stdnse.debug2(err)
      return nil
    end

    encoded[index] = res
  end

  return table.concat(encoded, delimiter)

end

-- This function breaks the tables of codepoints using a delimiter.
--
-- @param A table is given as an input which contains codepoints.
-- @param ASCII value of delimiter is provided.
-- @return Returns table of tables after breaking the give table using delimiter.
function breakInput(codepoints, delimiter)

  local tbl = {}
  local output = {}

  local delimiter = delimiter or 0x002E

  for _, v in ipairs(codepoints) do
    if v == delimiter then
      table.insert(output, tbl)
      tbl = {}
    else
      table.insert(tbl, v)
    end
  end

  table.insert(output, tbl)

  return output

end

---
-- This function converts the given domain name or string into a
-- ASCII string.
--
-- @param input Domain or string to be decoded.
-- @param decoder A decoder function to convert the domain into a
-- table of Unicode code points. Default: unicode.utf8_dec
-- @param encoder An encoder function to convert a Unicode code
-- point into a string of bytes.
-- @param decoder An decoder function to decode the input string
-- into an array of code points.
-- @return Returns decoded string in the desired format.
-- @return Throws an error, if any.
function encode(input, encoder, decoder)

  decoder = decoder or unicode.utf8_dec
  encoder = encoder or unicode.utf8_enc

  local decoded_tbl = unicode.decode(input, decoder)

  -- Works only for punycode.
  for _, val in pairs(regexSeparators) do
    decoded_tbl = find_and_replace(decoded_tbl, val, byte('.'))
  end

  local delimiterCodePoint = 0x002E
  -- Expects codepoints and delimiter values.
  local codepointLabels = breakInput(decoded_tbl, delimiterCodePoint)

  local stringLabels = {}

  for _, label in ipairs(codepointLabels) do
    table.insert(stringLabels, unicode.encode(label, encoder))
  end

  local delimiter = unicode.encode({0x002E}, encoder)

  return mapLabels(stringLabels, encode_label, decoder, delimiter)
end

---
-- This function converts the given domain name or string into a
-- Unicode string.
--
-- @param input Domain or string to be encoded.
-- @param encoder An encoder function to convert a Unicode code
-- point into a string of bytes.
-- @param decoder An decoder function to decode the input string
-- into an array of code points.
-- @return Returns encoded string in the desired format.
-- @return Throws an error, if any.
function decode(input, encoder, decoder)

  encoder = encoder or unicode.utf8_enc
  decoder = decoder or unicode.utf8_dec
  local delimiterCodePoint = 0x002E
  local delimiter = unicode.encode({0x002E}, encoder)

  local codepoints = unicode.decode(input, decoder)
  local codepointLabels = breakInput(codepoints, delimiterCodePoint)

  local stringLabels = {}

  for _, label in ipairs(codepointLabels) do
    table.insert(stringLabels, unicode.encode(label, encoder))
  end

  return mapLabels(stringLabels, decode_label, encoder, delimiter)

end

--Ignore the rest if we are not testing.
if not unittest.testing() then
  return _ENV
end

-- Table of punycode test cases.
local testCases = {
  {
    "xn--0zwm56d",
    "\xe6\xb5\x8b\xe8\xaf\x95"
  },
  {
    "xn--knigsgsschen-lcb0w",
    "k\xc3\xb6nigsg\xc3\xa4sschen"
  },
  {
    "xn--ab-fsf",
    "a\xe0\xa5\x8db"
  },
  {
    "xn--maana-pta",
    "ma\xc3\xb1ana"
  },
  {
    "xn----dqo34k",
    "\xe2\x98\x83-\xe2\x8c\x98"
  }
}

test_suite = unittest.TestSuite:new()

-- Running test cases against Encoding function.
for i, v in ipairs(testCases) do
  test_suite:add_test(unittest.equal(decode(v[1]), v[2]))
  test_suite:add_test(unittest.equal(encode(v[2]), v[1]))
end

return _ENV
