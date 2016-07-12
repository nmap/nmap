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

do
    local function test8 (a, b)
        local r = reverse(a, 8)
        if r ~= b then
            error(("0x%02X: expected 0x%02X, got 0x%02X"):format(a, b, r))
        end
    end
    test8(0x00, 0x00)
    test8(0x01, 0x80)
    test8(0x80, 0x01)
    test8(0xff, 0xff)
    test8(0x88, 0x11)
    test8(0x5c, 0x3a)

    local function test32 (a, b)
        local r = reverse(a, 32)
        if r ~= b then
            error(("0x%08X: expected 0x%08X, got 0x%08X"):format(a, b, r))
        end
    end
    test32(0x00000000, 0x00000000)
    test32(0x00000001, 0x80000000)
    test32(0x80000000, 0x00000001)
    test32(0xffffffff, 0xffffffff)
    test32(0x22221234, 0x2c484444)
end

return _ENV
