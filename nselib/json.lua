---
-- Library methods for handling JSON data. It handles JSON encoding and
-- decoding according to RFC 4627.
--
-- There is a test section at the bottom which shows some example
-- parsing. If you want to parse JSON, you can test it by pasting sample JSON
-- into the <code>TESTS</code> table and run the <code>test</code> method
--
-- There is a straightforward mapping between JSON and Lua data types. One
-- exception is JSON <code>NULL</code>, which is not the same as Lua
-- <code>nil</code>. (A better match for Lua <code>nil</code> is JavaScript
-- <code>undefined</code>.) <code>NULL</code> values in JSON are represented by
-- the special value <code>json.NULL</code>.
--
-- @author Martin Holst Swende (originally), David Fifield, Patrick Donnelly
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- TODO: Unescape/escape unicode
-- Version 0.4
-- Created 01/25/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Heavily modified 02/22/2010 - v0.3. Rewrote the parser into an OO-form, to not have to handle
-- all kinds of state with parameters and return values.
-- Modified 02/27/2010 - v0.4 Added unicode handling (written by David Fifield). Renamed toJson
-- and fromJson into generate() and parse(), implemented more proper numeric parsing and added some more error checking.

local bit = require "bit";
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unicode = require "unicode"
_ENV = stdnse.module("json", stdnse.seeall)

local lpeg = require "lpeg";
local locale = lpeg.locale;
local P = lpeg.P;
local R = lpeg.R;
local S = lpeg.S;
local V = lpeg.V;
local C = lpeg.C;
local Cb = lpeg.Cb;
local Cc = lpeg.Cc;
local Cf = lpeg.Cf;
local Cg = lpeg.Cg;
local Cp = lpeg.Cp;
local Cs = lpeg.Cs;
local Ct = lpeg.Ct;
local Cmt = lpeg.Cmt;

-- case sensitive keyword
local function K (a)
  return P(a) * -(locale().alnum + "_");
end

local NULL = {};
_M.NULL = NULL;

-- Encode a Unicode code point to UTF-8. See RFC 3629.
-- Does not check that cp is a real charaacter; that is, doesn't exclude the
-- surrogate range U+D800 - U+DFFF and a handful of others.
local function utf8_enc (cp)
  local result = {};
  local n, mask;

  if cp % 1.0 ~= 0.0 or cp < 0 then
    -- Only defined for nonnegative integers.
    error("utf code point defined only for non-negative integers");
  elseif cp <= 0x7F then
    -- Special case of one-byte encoding.
    return string.char(cp);
  elseif cp <= 0x7FF then
    n = 2;
    mask = 0xC0;
  elseif cp <= 0xFFFF then
    n = 3;
    mask = 0xE0;
  elseif cp <= 0x10FFFF then
    n = 4;
    mask = 0xF0;
  else
    assert(false);
  end

  while n > 1 do
    result[n] = 0x80 + bit.band(cp, 0x3F);
    cp = bit.rshift(cp, 6);
    n = n - 1;
  end
  result[1] = mask + cp;

  return string.char(unpack(result));
end

-- Decode a Unicode escape, assuming that self.pos starts just after the
-- initial \u. May consume an additional escape in the case of a UTF-16
-- surrogate pair. See RFC 2781 for UTF-16.
local unicode = P [[\u]] * C(locale().xdigit * locale().xdigit * locale().xdigit * locale().xdigit);
local function unicode16 (subject, position, hex)
  local cp = assert(tonumber(hex, 16));

  if cp < 0xD800 or cp > 0xDFFF then
    return position, utf8_enc(cp);
  elseif cp >= 0xDC00 and cp <= 0xDFFF then
    error(("Not a Unicode character: U+%04X"):format(cp));
  end

  -- Beginning of a UTF-16 surrogate.
  local lowhex = unicode:match(subject, position);

  if not lowhex then
    error(("Bad unicode escape \\u%s (missing low surrogate)"):format(hex))
  else
    local cp2 = assert(tonumber(lowhex, 16));
    if not (cp2 >= 0xDC00 and cp2 <= 0xDFFF) then
      error(("Bad unicode escape \\u%s\\u%s (bad low surrogate)"):format(hex, lowhex))
    end
    position = position+4;
    cp = 0x10000 + bit.band(cp, 0x3FF) * 0x400 + bit.band(cp2, 0x3FF)
    return position, utf8_enc(cp);
  end
end

-- call lpeg.locale on the grammar to add V "space"
local json = locale {
  V "json";

  json = V "space"^0 * V "value" * V "space"^0 * P(-1); -- FIXME should be 'V "object" + V "array"' instead of 'V "value"' ?

  value = V "string" +
          V "number" +
          V "object" +
          V "array" +
          K "true" * Cc(true)+
          K "false" * Cc(false)+
          K "null" * Cc(NULL);

  object = Cf(Ct "" * P "{" * V "space"^0 * (V "members")^-1 * V "space"^0 * P "}", rawset);
  members = V "pair" * (V "space"^0 * P "," * V "space"^0 * V "pair")^0;
  pair = Cg(V "string" * V "space"^0 * P ":" * V "space"^0 * V "value");

  array = Ct(P "[" * V "space"^0 * (V "elements")^-1 * V "space"^0 * P "]");
  elements = V "value" * V "space"^0 * (P "," * V "space"^0 * V "value")^0;

  string = Ct(P [["]] * (V "char")^0 * P [["]]) / table.concat;
  char = P [[\"]] * Cc [["]] +
         P [[\\]] * Cc [[\]] +
         P [[\b]] * Cc "\b" +
         P [[\f]] * Cc "\f" +
         P [[\n]] * Cc "\n" +
         P [[\r]] * Cc "\r" +
         P [[\t]] * Cc "\t" +
         P [[\u]] * Cmt(C(V "xdigit" * V "xdigit" * V "xdigit" * V "xdigit"), unicode16) +
         P [[\]] * C(1) +
         (C(1) - P [["]]);

  number = C((P "-")^-1 * V "space"^0 * (V "hexadecimal" + V "floating" + V "integer")) / function (a) return assert(tonumber(a)) end;
  hexadecimal = P "0x" * V "xdigit"^1;
  floating = (V "digit"^1 * P "." * V "digit"^0 + V "digit"^0 * P "." * V "digit"^1) * (V "exponent")^-1;
  integer = V "digit"^1 * (V "exponent")^-1;
  exponent = S "eE" * (S "-+")^-1 * V "digit"^1;
};
json = P(json); -- compile the grammar


--- Parses JSON data into a Lua object.
--
-- This is the method you probably want to use if you use this library from a
-- script.
--@param data a json string
--@return status true if ok, false if bad
--@return an object representing the json, or error message
function parse (data)
  local status, object = pcall(json.match, json, data);

  if not status then
    return false, object;
  elseif object then
    return true, object;
  else
    return false, "syntax error";
  end
end

--Some local shortcuts
local function dbg(str,...)
  stdnse.debug1("Json:"..str, ...)
end
local function d4(str,...)
  if nmap.debugging() > 3 then dbg(str, ...) end
end
local function d3(str,...)
  if nmap.debugging() > 2 then dbg(str, ...) end
end

--local dbg =stdnse.debug
local function dbg_err(str,...)
  stdnse.debug1("json-ERR:"..str, ...)
end

-- See section 2.5 for escapes.
-- For convenience, ESCAPE_TABLE maps to escape sequences complete with
-- backslash, and REVERSE_ESCAPE_TABLE maps from single escape characters
-- (no backslash).
local ESCAPE_TABLE = {}
local REVERSE_ESCAPE_TABLE = {}
do
  local escapes = {
    ["\x22"] = "\"",
    ["\x5C"] = "\\",
    ["\x2F"] = "/",
    ["\x08"] = "b",
    ["\x0C"] = "f",
    ["\x0A"] = "n",
    ["\x0D"] = "r",
    ["\x09"] = "t",
  }
  for k, v in pairs(escapes) do
    ESCAPE_TABLE[k] = "\\" .. v
    REVERSE_ESCAPE_TABLE[v] = k
  end
end

-- Escapes a string
--@param str the string
--@return a string where the special chars have been escaped
local function escape(str)
  return "\"" .. string.gsub(str, ".", ESCAPE_TABLE) .. "\""
end

--- Makes a table be treated as a JSON Array when generating JSON
--
-- A table treated as an Array has all non-number indices ignored.
-- @param t a table to be treated as an array
function make_array(t)
  local mt = getmetatable(t) or {}
  mt["json"] = "array"
  setmetatable(t, mt)
end

--- Makes a table be treated as a JSON Object when generating JSON
--
-- A table treated as an Object has all non-number indices ignored.
-- @param t a table to be treated as an object
function make_object(t)
  local mt = getmetatable(t) or {}
  mt["json"] = "object"
  setmetatable(t, mt)
end

--- Checks what JSON type a variable will be treated as when generating JSON
-- @param var a variable to inspect
-- @return a string containing the JSON type. Valid values are "array",
--        "object", "number", "string", "boolean", and "null"
function typeof(var)
  local t = type(var)
  if var == NULL then
    return "null"
  elseif t == "table" then
    local mtval = rawget(getmetatable(var) or {}, "json")
    if mtval == "array" or (mtval ~= "object" and #var > 0) then
      return "array"
    else
      return "object"
    end
  else
    return t
  end
  error("Unknown data type in typeof")
end

--- Creates json data from an object
--@param obj a table containing data
--@return a string containing valid json
function generate(obj)
  -- NULL-check must be performed before
  -- checking type == table, since the NULL-object
  -- is a table
  if obj == NULL then
    return "null"
  elseif obj == false then
    return "false"
  elseif obj == true then
    return "true"
  elseif type(obj) == "number" then
    return string.format("%g", obj)
  elseif type(obj) == "string" then
    return escape(obj)
  elseif type(obj) == "table" then
    local k, v, elems, jtype
    elems = {}
    jtype = typeof(obj)
    if jtype == "array" then
      for _, v in ipairs(obj) do
        elems[#elems + 1] = generate(v)
      end
      return "[" .. table.concat(elems, ", ") .. "]"
    elseif jtype == "object" then
      for k, v in pairs(obj) do
        elems[#elems + 1] = escape(k) .. ": " .. generate(v)
      end
      return "{" .. table.concat(elems, ", ") .. "}"
    end
  end
  error("Unknown data type in generate")
end

----------------------------------------------------------------------------------
-- Test-code for debugging purposes below
----------------------------------------------------------------------------------

local TESTS = {
  '{"a":1}',
  '{"a":true}',
  '{"a":     false}',
  '{"a":     null     \r\n, \t "b"  \f:"ehlo"}',
  '{"a\\"a":"a\\"b\\"c\\"d"}',
  '{"foo":"gaz\\"onk", "pi":3.14159,"hello":{ "wo":"rld"}}',
  '{"a":1, "b":2}',
  '{"foo":"gazonk", "pi":3.14159,"hello":{ "wo":"rl\\td"}}',
  '[1,2,3,4,5,null,false,true,"\195\164\195\165\195\182\195\177","bar"]',
  '[]',-- This will yield {} in toJson, since in lua there is only one basic datatype - and no difference when empty
  '{}',
  '',			-- error
  'null',			-- error
  '"abc"',		-- error
  '{a":1}', -- error
  '{"a" bad :1}', -- error
  '["a\\\\t"]',  -- Should become Lua {"a\\t"}
  '[0.0.0]',  -- error
  '[-1]',
  '[-1.123e-2]',
  '[5e3]',
  '[5e+3]',
  '[5E-3]',
  '[5.5e3]',
  '["a\\\\"]',  -- Should become Lua {"a\\"}
  '{"a}": 1}',  -- Should become Lua {"a}" = 1}
  '["key": "value"]',  -- error
  '["\\u0041"]',  -- Should become Lua {"A"}
  '["\\uD800"]',  -- error
  '["\\uD834\\uDD1EX"]',  -- Should become Lua {"\240\157\132\158X"}
}
function test()
  print("Tests running")
  local i,v,res,status
  for i,v in pairs(TESTS) do
    print("----------------------------")
    print(("%q"):format(v))
    status,res = parse(v)
    if not status then print( res) end
    if(status) then
		  print(("%q"):format(generate(res)))
    else
      print("Error:".. res)
    end
  end
end

return _ENV;
