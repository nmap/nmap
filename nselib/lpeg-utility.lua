---
-- Utility functions for LPeg.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name lpeg-utility

local assert = assert

local lpeg = require "lpeg"
local stdnse = require "stdnse"
local pairs = pairs
local string = require "string"
local tonumber = tonumber
local rawset = rawset

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

---
-- Returns a pattern which captures the contents of a quoted string.
--
-- This can handle embedded escaped quotes, and captures the unescaped string.
--
-- @param quot The quote character to use. Default: '"'
-- @param esc The escape character to use. Cannot be the same as quot. Default: "\"
function escaped_quote (quot, esc)
  quot = quot or '"'
  esc = esc or '\\'
  return lpeg.P {
    lpeg.Cs(lpeg.V "quot" * lpeg.Cs((lpeg.V "simple_char" + lpeg.V "noesc" + lpeg.V "unesc")^0) * lpeg.V "quot"),
    quot = lpeg.P(quot)/"",
    esc = lpeg.P(esc),
    simple_char = (lpeg.P(1) - (lpeg.V "quot" + lpeg.V "esc")),
    unesc = (lpeg.V "esc" * lpeg.C( lpeg.V "esc" + lpeg.P(quot) ))/"%1",
    noesc = lpeg.V "esc" * lpeg.V "simple_char"
  }
end

---
-- Adds hooks to a grammar to print debugging information
--
-- Debugging LPeg grammars can be difficult. Calling this function on your
-- grammmar will cause it to print ENTER and LEAVE statements for each rule, as
-- well as position and subject after each successful rule match.
--
-- For convenience, the modified grammar is returned; a copy is not made
-- though, and the original grammar is modified as well.
--
-- @param grammar The LPeg grammar to modify
-- @param printer A printf-style formatting printer function to use.
--                Default: stdnse.debug1
-- @return The modified grammar.
function debug (grammar, printer)
  printer = printer or stdnse.debug1
  -- Original code credit: http://lua-users.org/lists/lua-l/2009-10/msg00774.html
  for k, p in pairs(grammar) do
    local enter = lpeg.Cmt(lpeg.P(true), function(s, p, ...)
      printer("ENTER %s", k) return p end)
    local leave = lpeg.Cmt(lpeg.P(true), function(s, p, ...)
      printer("LEAVE %s", k) return p end) * (lpeg.P("k") - lpeg.P "k");
    grammar[k] = lpeg.Cmt(enter * p + leave, function(s, p, ...)
      printer("---%s---", k) printer("pos: %d, [%s]", p, s:sub(1, p-1)) return p end)
  end
  return grammar
end

do
  -- Cache the returned pattern
  local getquote = escaped_quote()

  -- Substitution pattern to unescape a string
  local unescape = lpeg.P {
    -- Substitute captures
    lpeg.Cs((lpeg.V "simple_char" + lpeg.V "unesc")^0),
    -- Escape char is '\'
    esc = lpeg.P "\\",
    -- Simple char is anything but escape char
    simple_char = lpeg.P(1) - lpeg.V "esc",
    -- If we hit an escape, process specials or hex code, otherwise remove the escape
    unesc = (lpeg.V "esc" * lpeg.Cs( lpeg.V "specials" + lpeg.V "code" + lpeg.P(1) ))/"%1",
    -- single-char escapes. These are the only ones service_scan uses
    specials = lpeg.S "trn0" / {t="\t", r="\r", n="\n", ["0"]="\0"},
    -- hex escape: convert to char
    code = (lpeg.P "x" * lpeg.C(lpeg.S "0123456789abcdefABCDEF"^-2))/function(c)
    return string.char(tonumber(c,16)) end,
  }

  --- Turn the service fingerprint reply to a probe into a binary blob
  --@param fp the <code>port.version.service_fp</code> provided by the NSE API.
  --@param probe the probe name to match, e.g. GetRequest, TLSSessionReq, etc.
  --@return the raw probe response received to that probe, or nil if there was no response.
  function get_response (fp, probe)
    fp = string.gsub(fp, "\nSF:", "")
    local i, e = string.find(fp, string.format("%s,%%x+,", probe))
    if i == nil then return nil end
    return unescape:match(getquote:match(fp, e+1))
  end

  local svfp_parser = lpeg.P ({
      anywhere("%r(") * lpeg.Cf(lpeg.Ct("") * (lpeg.V "probematch" * lpeg.P(")%r(")^-1)^1, rawset),
      probematch = lpeg.Cg(lpeg.C((lpeg.P(1) - ",")^1) * "," * (lpeg.R("09") + lpeg.R("AF"))^1 * "," * lpeg.Cs(getquote/function(q) return unescape:match(q) end)),
    })
  --- Get the service fingerprint reply to a probe into a binary blob
  --@param fp the <code>port.version.service_fp</code> provided by the NSE API.
  function parse_fp (fp)
    fp = string.gsub(fp, "\nSF:", "")
    return svfp_parser:match(fp)
  end
end

return _ENV
