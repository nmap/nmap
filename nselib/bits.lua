---
-- Bit manipulation library.
--
-- @author Patrick Donnelly <batrick@batbytes.com>
-- @copyright Same as Nmap -- see https://nmap.org/book/man-legal.html
-- @see https://www.lua.org/manual/5.3/manual.html#3.4.2
--
-- @class module
-- @name bits

local assert = assert
local error = error
local unittest = require "unittest"

local _ENV = {}

--- Reverses bits in integer.
--
-- @param n The integer.
-- @param size The bit width of the integer (default: 8).
-- @return The reversed integer.
function reverse (n, size)
    if not size or size == 8 then
        n = n & 0xff
        n = (n & 0xf0) >> 4 | (n & 0x0f) << 4
        n = (n & 0xcc) >> 2 | (n & 0x33) << 2
        n = (n & 0xaa) >> 1 | (n & 0x55) << 1
        n = n & 0xff
    elseif size == 32 then
        n = n & 0xffffffff
        n = ((n >> 1) & 0x55555555) | ((n & 0x55555555) << 1);
        n = ((n >> 2) & 0x33333333) | ((n & 0x33333333) << 2);
        n = ((n >> 4) & 0x0F0F0F0F) | ((n & 0x0F0F0F0F) << 4);
        n = ((n >> 8) & 0x00FF00FF) | ((n & 0x00FF00FF) << 8);
        n = ( n >> 16             ) | ( n               << 16);
        n = n & 0xffffffff
    else
        error("invalid size: "..size)
    end
    return n
end

--- Returns <code>a</code> arithmetically right-shifted by <code>b</code>
-- places.
-- @param a Number to perform the shift on.
-- @param b Number of shifts.
function arshift(a, b)
    if a < 0 then
        if a % 2 == 0 then -- even?
            return a // (1<<b)
        else
            return a // (1<<b) + 1
        end
    else
        return a >> b
    end
end

if not unittest.testing() then
  return _ENV
end

local equal = unittest.equal

test_suite = unittest.TestSuite:new()
test_suite:add_test(equal(reverse(0x00, 8), 0x00), "reverse 8-bit number")
test_suite:add_test(equal(reverse(0x01, 8), 0x80), "reverse 8-bit number")
test_suite:add_test(equal(reverse(0x80, 8), 0x01), "reverse 8-bit number")
test_suite:add_test(equal(reverse(0xff, 8), 0xff), "reverse 8-bit number")
test_suite:add_test(equal(reverse(0x88, 8), 0x11), "reverse 8-bit number")
test_suite:add_test(equal(reverse(0x5c, 8), 0x3a), "reverse 8-bit number")

test_suite:add_test(equal(reverse(0x00000000, 32), 0x00000000), "reverse 32-bit number")
test_suite:add_test(equal(reverse(0x00000001, 32), 0x80000000), "reverse 32-bit number")
test_suite:add_test(equal(reverse(0x80000000, 32), 0x00000001), "reverse 32-bit number")
test_suite:add_test(equal(reverse(0xffffffff, 32), 0xffffffff), "reverse 32-bit number")
test_suite:add_test(equal(reverse(0x22221234, 32), 0x2c484444), "reverse 32-bit number")

return _ENV
