---
-- Formula functions for various calculations.
--
-- The library lets scripts to use common mathematical functions to compute percentages,
-- averages, entropy, randomness and other calculations. Scripts that generate statistics
-- and metrics can also make use of this library.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local bin = require "bin"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("formulas", stdnse.seeall)

--- Calculate the entropy of a password.
--
-- A random password's information entropy, H, is given by the formula: H = L *
-- (logN) / (log2), where N is the number of possible symbols and L is the
-- number of symbols in the password. Based on
-- https://en.wikipedia.org/wiki/Password_strength
-- @param value The password to check
-- @return The entropy in bits
calcPwdEntropy = function(value)

    local total, hasdigit, haslower, hasupper, hasspaces = 0, 0, 0, 0, false

    if string.find(value, "%d") then
        hasdigit = 1
    end
    if string.find(value, "%l") then
        haslower = 1
    end
    if string.find(value, "%u") then
        hasupper = 1
    end
    if string.find(value, ' ') then
        hasspaces = true
    end

    -- The values 10, 26, 26 have been taken from Wikipedia's entropy table.
    local total = hasdigit * 10 + hasupper * 26 + haslower * 26
    local entropy = math.floor(math.log(total) * #value / math.log(2))

    return entropy
end

-- A chi-square test for the null hypothesis that the members of data are drawn
-- from a uniform distribution over num_cats categories.
local function chi2(data, num_cats)
    local bins = {}
    local x2, delta, expected

    for _, x in ipairs(data) do
        bins[x] = bins[x] or 0
        bins[x] = bins[x] + 1
    end

    expected = #data / num_cats
    x2 = 0.0
    for _, n in pairs(bins) do
        delta = n - expected
        x2 = x2 + delta * delta
    end
    x2 = x2 / expected

    return x2
end

-- Split a string into a sequence of bit strings of the given length.
-- splitbits("abc", 5) --> {"01100", "00101", "10001", "00110"}
-- Any short final group is omitted.
local function splitbits(s, n)
    local seq

    local _, bits = bin.unpack("B" .. #s, s)
    seq = {}
    for i = 1, #bits - n, n do
        seq[#seq + 1] = bits:sub(i, i + n - 1)
    end

    return seq
end

-- chi-square cdf table at 0.95 confidence for different degrees of freedom.
-- >>> import scipy.stats, scipy.optimize
-- >>> scipy.optimize.newton(lambda x: scipy.stats.chi2(dof).cdf(x) - 0.95, dof)
local CHI2_CDF = {
    [3] = 7.8147279032511738,
    [15] = 24.99579013972863,
    [255] = 293.2478350807001,
}

--- Checks whether a sample looks random
--
-- Because our sample is so small (only 16 bytes), do a chi-square
-- goodness of fit test across groups of 2, 4, and 8 bits. If using only
-- 8 bits, for example, any sample whose bytes are all different would
-- pass the test. Using 2 bits will tend to catch things like pure
-- ASCII, where one out of every four samples never has its high bit
-- set.
-- @param data The data to check
-- @return True if the data appears to be random, false otherwise
function looksRandom(data)
    local x2


    x2 = chi2(splitbits(data, 2), 4)
    if x2 > CHI2_CDF[3] then
        return false
    end

    x2 = chi2(splitbits(data, 4), 16)
    if x2 > CHI2_CDF[15] then
        return false
    end

    x2 = chi2({string.byte(data, 1, -1)}, 256)
    if x2 > CHI2_CDF[255] then
        return false
    end

    return true
end

return _ENV
