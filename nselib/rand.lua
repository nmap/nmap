--- Functions for generating random data
--
-- The strings generated here are not cryptographically secure, but they should
-- be sufficient for most purposes.
--
-- @author Daniel Miller
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name rand

local require = require
local have_openssl, openssl = pcall(require, "openssl")

local math = require "math"
local random = math.random

local string = require "string"
local byte = string.byte
local char = string.char
local sub = string.sub

local table = require "table"
local concat = table.concat

local type = type
local _ENV = {}

local get_random_bytes
if have_openssl then
  get_random_bytes = openssl.rand_pseudo_bytes
else
  get_random_bytes = require "nmap".get_random_bytes
end

--- Generate a random string.
--
-- You can either provide your own charset or the function will generate random
-- bytes, which may include null bytes.
-- @param len Length of the string we want to generate.
-- @param charset Charset that will be used to generate the string. String or table
-- @return A random string of length <code>len</code> consisting of
-- characters from <code>charset</code> if one was provided, or random bytes otherwise.
random_string = function(len, charset)
  local t = {}
  if charset then
    if type(charset) == "string" then
      for i=1,len do
        local r = random(#charset)
        t[i] = sub(charset, r, r)
      end
    else
      for i=1,len do
        t[i]=charset[random(#charset)]
      end
    end
  else
    return get_random_bytes(len)
  end
  return concat(t)
end
local random_string = random_string

--- Generate a charset that can be passed to <code>random_string</code>
--
-- @param left_bound The lower bound character or byte value of the set
-- @param right_bound The upper bound character or byte value of the set
-- @param charset Optional, a charset table to augment. By default a new charset is created.
-- @return A charset table
function charset(left_bound, right_bound, charset)
  local t = charset or {}
  left_bound = type(left_bound)=="string" and byte(left_bound) or left_bound
  right_bound = type(right_bound)=="string" and byte(right_bound) or right_bound
  if left_bound > right_bound then
    return t
  end
  for i=left_bound,right_bound do
    t[#t+1] = char(i)
  end
  return t
end
local charset = charset

local alpha_charset = charset('a', 'z')
--- Generate a random alpha word
--
-- Convenience wrapper around <code>random_string</code> to generate a random
-- string of lowercase alphabetic characters.
-- @param len The length of word to return
-- @return A string of random characters between 'a' and 'z' inclusive.
function random_alpha (len)
  return random_string(len, alpha_charset)
end

return _ENV
