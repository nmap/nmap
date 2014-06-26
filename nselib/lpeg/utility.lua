---
-- Utility functions for LPeg.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @class module
-- @name lpeg.utility

local assert = assert

local lpeg = require "lpeg"
local stdnse = require "stdnse"

_ENV = {}

---
-- Returns a pattern which matches the literal string caselessly.
--
-- @param literal A literal string to match case-insensitively.
-- @return An LPeg pattern.
function caseless (literal)
  local caseless = lpeg.Cf((lpeg.P(1) / function (a) return lpeg.S(a:lower()..a:upper()) end)^1, function (a, b) return a * b end)
  return assert(caseless:match(literal))
end

---
-- Returns a pattern which matches the input pattern anywhere on a subject string.
--
-- @param patt Input pattern.
-- @return An LPeg pattern.
function anywhere (patt)
  return lpeg.P {
    patt + 1 * lpeg.V(1)
  }
end

---
-- Adds the current locale from lpeg.locale() to the grammar and returns the final pattern.
--
-- @param grammar Input grammar.
-- @return An LPeg pattern.
function localize (grammar)
  return lpeg.P(lpeg.locale(grammar))
end

---
-- Splits the input string on the input separator.
--
-- @param str Input string to split.
-- @param sep Input string/pattern to separate on.
-- @return All splits.
function split (str, sep)
  return lpeg.P {
    lpeg.V "elem" * (lpeg.V "sep" * lpeg.V "elem")^0,
    elem = lpeg.C((1 - lpeg.V "sep")^0),
    sep = sep,
  } :match(str)
end

---
-- Returns a pattern which only matches at a word boundary (beginning).
--
-- Essentially the same as '\b' in a PCRE pattern.
--
-- @param patt A pattern.
-- @return A new LPeg pattern.
function atwordboundary (patt)
  return _ENV.localize {
    patt + lpeg.V "alpha"^0 * (1 - lpeg.V "alpha")^1 * lpeg.V(1)
  }
end

return _ENV
