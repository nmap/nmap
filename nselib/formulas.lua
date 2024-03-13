---
-- Formula functions for various calculations.
--
-- The library lets scripts to use common mathematical functions to compute percentages,
-- averages, entropy, randomness and other calculations. Scripts that generate statistics
-- and metrics can also make use of this library.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

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

local function c_to_bin (c)
  local n = stdnse.tobinary(c:byte())
  return ("0"):rep(8-#n)..n
end

-- Split a string into a sequence of bit strings of the given length.
-- splitbits("abc", 5) --> {"01100", "00101", "10001", "00110"}
-- Any short final group is omitted.
local function splitbits(s, n)
    local bits = s:gsub(".", c_to_bin)

    local seq = {}
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

--- Return the mean and sample standard deviation of an array, using the
-- algorithm from Knuth Vol. 2, Section 4.2.2.
--
-- @params t An array-style table of values
-- @return The mean of the values
-- @return The standard deviation of the values
function mean_stddev(t)
  local i, m, s, sigma

  if #t == 0 then
    return nil, nil
  elseif #t == 1 then
    return t[1], 0
  end

  m = t[1]
  s = 0
  for i = 2, #t do
    local mp = m
    m = m + (t[i] - m) / i
    s = s + (t[i] - mp) * (t[i] - m)
  end
  sigma = math.sqrt(s / (#t - 1))

  return m, sigma
end

-- Partition function for quickselect and quicksort
local function partition(t, left, right, pivot)
  local pv = t[pivot]
  t[pivot], t[right] = t[right], t[pivot]
  local storeidx = left
  for i=left, right-1 do
    assert(storeidx < right)
    if t[i] < pv then
      t[storeidx], t[i] = t[i], t[storeidx]
      storeidx = storeidx + 1
    end
  end
  t[storeidx], t[right] = t[right], t[storeidx]
  return storeidx
end

-- Quickselect algorithm
local function _qselect(t, left, right, k)
  if left == right then
    return t[left]
  end
  local pivot = math.random(left, right)
  pivot = partition(t, left, right, pivot)
  if k == pivot then
    return t[k]
  elseif k < pivot then
    return _qselect(t, left, pivot - 1, k)
  else
    return _qselect(t, pivot + 1, right, k)
  end
end

--- Return the k-th largest element in a list
--
-- @param t The list, not sorted
-- @param k The ordinal value to return
-- @return The k-th largest element in the list
function quickselect(t, k)
  local tc = {}
  -- Work on a copy of the table, since we modify in-place
  table.move(t, 1, #t, 1, tc)
  return _qselect(tc, 1, #tc, k)
end

--- Find the median of a list
--
--@param t the table/list of values
--@return the median value
function median(t)
  return quickselect(t, math.ceil(#t/2))
end

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

local table_equal = unittest.table_equal
test_suite:add_test(table_equal(splitbits("abc", 5), {"01100", "00101", "10001", "00110"}), 'splitbits("abc", 5)')
return _ENV
