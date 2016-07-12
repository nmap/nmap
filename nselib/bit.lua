---
-- Bitwise operations on integers.
--
-- THIS LIBRARY IS DEPRECATED, Please use native Lua 5.3 bitwise operators.
--
-- @copyright BSD License
-- @see https://www.lua.org/manual/5.3/manual.html#3.4.2
-- @class module
-- @name bit

local select = select

local mininteger = require "math".mininteger

local _ENV = {}

--- Returns the one's complement of <code>a</code>.
-- @param a Number.
-- @return The one's complement of <code>a</code>.
function bnot(a)
    return ~a
end

--- Returns the bitwise and of all its arguments.
-- @param ... A variable number of Numbers to and.
-- @return The anded result.
function band(a, b, ...)
    a = a & b
    if select("#", ...) > 0 then
        return band(a, ...)
    else
        return a
    end
end

--- Returns the bitwise or of all its arguments.
-- @param ... A variable number of Numbers to or.
-- @return The ored result.
function bor(a, b, ...)
    a = a | b
    if select("#", ...) > 0 then
        return bor(a, ...)
    else
        return a
    end
end

--- Returns the bitwise exclusive or of all its arguments.
-- @param ... A variable number of Numbers to exclusive or.
-- @return The exclusive ored result.
function bxor(a, b, ...)
    a = a ~ b
    if select("#", ...) > 0 then
        return bxor(a, ...)
    else
        return a
    end
end

--- Returns <code>a</code> left-shifted by <code>b</code> places.
-- @param a Number to perform the shift on.
-- @param b Number of shifts.
function lshift(a, b)
    return a << b
end

--- Returns <code>a</code> right-shifted by <code>b</code> places.
-- @param a Number to perform the shift on.
-- @param b Number of shifts.
function rshift(a, b)
    return a >> b
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

--- Returns the integer remainder of <code>a</code> divided by <code>b</code>.
-- @param a Dividend.
-- @param b Divisor.
function mod(a, b)
    return a % b
end

return _ENV
