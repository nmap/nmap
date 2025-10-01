---
-- URI parsing, composition, and relative URL resolution.
--
-- A URL is represented as a table with the following entries:
-- * <code>scheme</code>
-- * <code>fragment</code>
-- * <code>query</code>
-- * <code>params</code>
-- * <code>authority</code>
-- * <code>userinfo</code>
-- * <code>path</code>
-- * <code>port</code>
-- * <code>password</code>
-- These correspond to these parts of a URL (some may be <code>nil</code>):
-- <code>
-- scheme://userinfo@password:authority:port/path;params?query#fragment
-- </code>
--
-- @author Diego Nehab
-- @author Eddie Bell <ejlbell@gmail.com>

--[[
URI parsing, composition and relative URL resolution
LuaSocket toolkit.
Author: Diego Nehab
RCS ID: $Id: url.lua,v 1.37 2005/11/22 08:33:29 diego Exp $

parse_query and build_query added For nmap (Eddie Bell <ejlbell@gmail.com>)
--]]

-----------------------------------------------------------------------------
-- Declare module
-----------------------------------------------------------------------------

local _G = require "_G"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local idna = require "idna"
local tableaux = require "tableaux"
local unicode = require "unicode"
local unittest = require "unittest"
local base = _G


_ENV = stdnse.module("url", stdnse.seeall)

_VERSION = "URL 1.0"

--[[ Internal functions --]]

local function make_set(t)
  local s = {}
  for i,v in base.ipairs(t) do
    s[t[i]] = 1
  end
  return s
end

local function hex_esc (c)
  return string.format("%%%02X", string.byte(c))
end

-- these are allowed within a path segment, along with alphanum
-- other characters must be escaped
local segment_set = make_set {
  "-", "_", ".", "!", "~", "*", "'", "(",
  ")", ":", "@", "&", "=", "+", "$", ",",
}
setmetatable(segment_set, { __index = function(t, c) return hex_esc(c) end })

---
-- Protects a path segment, to prevent it from interfering with the
-- URL parsing.
-- @param s Binary string to be encoded.
-- @return Escaped representation of string.
local function protect_segment(s)
  return string.gsub(s, "([^A-Za-z0-9_.~-])", segment_set)
end

---
-- Builds a path from a base path and a relative path
-- @param base_path A base path.
-- @param relative_path A relative path.
-- @return The corresponding absolute path.
-----------------------------------------------------------------------------
local function absolute_path(base_path, relative_path)
  -- Function for normalizing trailing dot and dot-dot by adding the final /
  local fixdots = function (s)
                    return s:gsub("%f[^/\0]%.$", "./"):gsub("%f[^/\0]%.%.$", "../")
                  end
  local path = relative_path
  if path:sub(1, 1) ~= "/" then
    -- function wrapper to avoid %-substitution of captures
    path = fixdots(base_path):gsub("[^/]*$", function() return path end)
  end
  -- Break the path into segments, processing dot and dot-dot
  local segs = {}
  for s in fixdots(path):gmatch("[^/]*") do
    if s == "." then -- ignore
    elseif s == ".." then -- remove the previous segment
      if #segs > 1 or (#segs == 1 and segs[#segs] ~= "") then
        table.remove(segs)
      end
    else -- add a regular segment, possibly empty
      table.insert(segs, s)
    end
  end
  return table.concat(segs, "/")
end


--[[ External functions --]]

---
-- Encodes a string into its escaped hexadecimal representation.
-- @param s Binary string to be encoded.
-- @return Escaped representation of string.
-----------------------------------------------------------------------------
function escape(s)
  return (string.gsub(s, "([^A-Za-z0-9_.~-])", hex_esc))
end


local function hex_unesc (hex)
    return string.char(base.tonumber(hex, 16))
end

---
-- Decodes an escaped hexadecimal string.
-- @param s Hexadecimal-encoded string.
-- @return Decoded string.
-----------------------------------------------------------------------------
function unescape(s)
  return (string.gsub(s, "%%(%x%x)", hex_unesc))
end

local function normalize_escape (s)
  return escape(unescape(s))
end

function ascii_hostname(host)
  local hostname = stdnse.get_hostname(host)
  if hostname:match("[\x80-\xff]") then
    -- TODO: Allow other Unicode encodings
    local decoded = unicode.decode(hostname, unicode.utf8_dec)
    if decoded then
      local ascii_host = idna.toASCII(decoded)
      if ascii_host then
        hostname = ascii_host
      end
    end
  end
  return hostname
end

---
-- Parses a URL and returns a table with all its parts according to RFC 3986.
--
-- The following grammar describes the names given to the URL parts.
-- <code>
-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
-- <authority> ::= <userinfo>@<host>:<port>
-- <userinfo> ::= <user>[:<password>]
-- <path> :: = {<segment>/}<segment>
-- </code>
--
-- The leading <code>/</code> in <code>/<path></code> is considered part of
-- <code><path></code>.
--
-- If the host contains non-ASCII characters, the Punycode-encoded version of
-- the host name will be in the <code>ascii_host</code> field of the returned
-- table.
--
-- @param url URL of request.
-- @param default Table with default values for each field.
-- @return A table with the following fields, where RFC naming conventions have
--   been preserved:
--     <code>scheme</code>, <code>authority</code>, <code>userinfo</code>,
--     <code>user</code>, <code>password</code>,
--     <code>host</code>, <code>ascii_host</code>,
--     <code>port</code>, <code>path</code>, <code>params</code>,
--     <code>query</code>, and <code>fragment</code>.
-----------------------------------------------------------------------------
function parse(url, default)
  -- initialize default parameters
  local parsed = {}

  for i,v in base.pairs(default or parsed) do parsed[i] = v end
  -- remove whitespace
  -- url = string.gsub(url, "%s", "")
  -- Decode unreserved characters
  url = string.gsub(url, "%%%x%x", normalize_escape)
  -- get fragment
  url = string.gsub(url, "#(.*)$", function(f)
    parsed.fragment = f
    return ""
  end)
  -- get scheme. Lower-case according to RFC 3986 section 3.1.
  url = string.gsub(url, "^(%w[%w.+-]*):",
  function(s) parsed.scheme = string.lower(s); return "" end)
  -- get authority
  url = string.gsub(url, "^//([^/]*)", function(n)
    parsed.authority = n
    return ""
  end)
  -- get query stringing
  url = string.gsub(url, "%?(.*)", function(q)
    parsed.query = q
    return ""
  end)
  -- get params
  url = string.gsub(url, "%;(.*)", function(p)
    parsed.params = p
    return ""
  end)

  -- path is whatever was left
  parsed.path = url

  -- Checks for folder route and extension
  if parsed.path:sub(-1) == "/" then
    parsed.is_folder = true
  else
    parsed.is_folder = false
    parsed.extension = parsed.path:match("%.([^/.;]+)%f[;\0][^/]*$")
  end

  -- Represents host:port, port = nil if not used.
  local authority = parsed.authority
  if not authority then return parsed end
  authority = string.gsub(authority,"^([^@]*)@",
                function(u) parsed.userinfo = u; return "" end)
  authority = string.gsub(authority, ":(%d+)$",
                function(p) parsed.port = tonumber(p); return "" end)
  if authority ~= "" then parsed.host = authority end
  if parsed.host then
    parsed.ascii_host = ascii_hostname(parsed.host)
  end
  local userinfo = parsed.userinfo
  if not userinfo then return parsed end
  userinfo = string.gsub(userinfo, ":([^:]*)$",
               function(p) parsed.password = p; return "" end)
  parsed.user = userinfo
  return parsed
end

---
-- Rebuilds a parsed URL from its components.
--
-- Components are protected if any reserved or disallowed characters are found.
-- @param parsed Parsed URL, as returned by parse.
-- @return A string with the corresponding URL.
-----------------------------------------------------------------------------
function build(parsed)
  local ppath = parse_path(parsed.path or "")
  local url = build_path(ppath)
  if parsed.params then url = url .. ";" .. parsed.params end
  if parsed.query then url = url .. "?" .. parsed.query end
  local authority = parsed.authority
  if parsed.host then
    authority = parsed.host
    if parsed.port then authority = authority .. ":" .. parsed.port end
    local userinfo = parsed.userinfo
    if parsed.user then
      userinfo = parsed.user
      if parsed.password then
        userinfo = userinfo .. ":" .. parsed.password
      end
    end
    if userinfo then authority = userinfo .. "@" .. authority end
  end
  if authority then url = "//" .. authority .. url end
  if parsed.scheme then url = parsed.scheme .. ":" .. url end
  if parsed.fragment then url = url .. "#" .. parsed.fragment end
  -- url = string.gsub(url, "%s", "")
  return url
end

---
-- Builds an absolute URL from a base and a relative URL according to RFC 2396.
-- @param base_url A base URL.
-- @param relative_url A relative URL.
-- @return The corresponding absolute URL.
-----------------------------------------------------------------------------
function absolute(base_url, relative_url)
  local base_parsed;
  if type(base_url) == "table" then
    base_parsed = base_url
    base_url = build(base_parsed)
  else
    base_parsed = parse(base_url)
  end
  local relative_parsed = parse(relative_url)
  if not base_parsed then return relative_url
  elseif not relative_parsed then return base_url
  elseif relative_parsed.scheme then return relative_url
  else
    relative_parsed.scheme = base_parsed.scheme
    if not relative_parsed.authority then
      relative_parsed.authority = base_parsed.authority
      if not relative_parsed.path then
        relative_parsed.path = base_parsed.path
        if not relative_parsed.params then
          relative_parsed.params = base_parsed.params
          if not relative_parsed.query then
            relative_parsed.query = base_parsed.query
          end
        end
      else
        relative_parsed.path = absolute_path(base_parsed.path or "",
        relative_parsed.path)
      end
    end
    return build(relative_parsed)
  end
end

---
-- Breaks a path into its segments, unescaping the segments.
-- @param path A path to break.
-- @return A table with one entry per segment.
-----------------------------------------------------------------------------
function parse_path(path)
  local parsed = {}
  if path == nil or path == "" then
    return parsed
  end
  for slashes, segment in string.gmatch(path, "(/*)([^/]*)") do
    -- Append empty segments to ensure presence of consecutive `/` isn't lost.
    for _ = 1, string.len(slashes) - 1 do
          table.insert(parsed, "")
    end
    -- Append path segment
    if segment ~= "" then
        table.insert(parsed, segment)
    end
  end
  for i, v in ipairs(parsed) do
    parsed[i] = unescape(v)
  end
  if string.sub(path, 1, 1) == "/" then parsed.is_absolute = 1 end
  if string.sub(path, -1, -1) == "/" then parsed.is_directory = 1 end
  return parsed
end

---
-- Builds a path component from its segments, escaping protected characters.
-- @param parsed Path segments.
-- @param unsafe If true, segments are not protected before path is built.
-- @return The corresponding path string
-----------------------------------------------------------------------------
function build_path(parsed, unsafe)
  local path = {}
  if parsed.is_absolute then path[#path+1] = "/" end
  local n = #parsed
  if unsafe then
    for i = 1, n-1 do
      path[#path+1] = parsed[i] .. "/"
    end
    if n > 0 then
      path[#path+1] = parsed[n]
      if parsed.is_directory then path[#path+1] = "/" end
    end
  else
    for i = 1, n-1 do
      path[#path+1] = protect_segment(parsed[i]) .. "/"
    end
    if n > 0 then
      path[#path+1] = protect_segment(parsed[n])
      if parsed.is_directory then path[#path+1] = "/" end
    end
  end
  return table.concat(path)
end

local entities = {
  ["amp"] = "&",
  ["lt"] = "<",
  ["gt"] = ">"
}
---
-- Breaks a query string into name/value pairs.
--
-- This function takes a <code><query></code> of the form
-- <code>"name1=value1&name2=value2"</code>
-- and returns a table containing the name-value pairs, with the name as the key
-- and the value as its associated value. Both the name and the value are
-- subject to URL decoding.
-- @param query Query string.
-- @return A table of name-value pairs following the pattern
-- <code>table["name"]</code> = <code>value</code>.
-----------------------------------------------------------------------------
function parse_query(query)
  local parsed = {}
  local pos = 1

  query = string.gsub(query, "&([ampltg]+);", entities)

  local function ginsert(qstr)
    local pos = qstr:find("=", 1, true)
    if pos then
      parsed[unescape(qstr:sub(1, pos - 1))] = unescape(qstr:sub(pos + 1))
    else
      parsed[unescape(qstr)] = ""
    end
  end

  while true do
    local first, last = string.find(query, "&", pos, true)
    if first then
      ginsert(string.sub(query, pos, first-1));
      pos = last+1
    else
      ginsert(string.sub(query, pos));
      break;
    end
  end
  return parsed
end

---
-- Builds a query string from a table.
--
-- This is the inverse of <code>parse_query</code>. Both the parameter name
-- and value are subject to URL encoding.
-- @param query A dictionary table where <code>table['name']</code> =
-- <code>value</code>.
-- @return A query string (like <code>"name=value2&name=value2"</code>).
-----------------------------------------------------------------------------
function build_query(query)
  local qstr = {}

  for i,v in pairs(query) do
    qstr[#qstr+1] = escape(i) .. '=' .. escape(v)
  end
  return table.concat(qstr, '&')
end

local get_default_port_ports = {http=80, https=443}
---
-- Provides the default port for a given URI scheme.
--
-- @param scheme for determining the port, such as "http" or "https".
-- @return A port number as an integer, such as 443 for scheme "https",
--         or nil in case of an undefined scheme
function get_default_port (scheme)
  return get_default_port_ports[(scheme or ""):lower()]
end

get_default_scheme_schemes = tableaux.invert(get_default_port_ports)

---
-- Provides the default URI scheme for a given port.
--
-- @param port A port number as a number or port table
-- @return scheme for addressing the port, such as "http" or "https".
-----------------------------------------------------------------------------
function get_default_scheme (port)
  local number = (type(port) == "number") and port or port.number
  return get_default_scheme_schemes[number]
end

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

local test_urls = {
  { _url = "https://dummy:pass@example.com:9999/example.ext?k1=v1&k2=v2#fragment=/",
    _res = {
      scheme = "https",
      authority = "dummy:pass@example.com:9999",
      userinfo = "dummy:pass",
      user = "dummy",
      password = "pass",
      host = "example.com",
      port = 9999,
      path = "/example.ext",
      query = "k1=v1&k2=v2",
      fragment = "fragment=/",
      is_folder = false,
      extension = "ext",
    },
    _nil = {"params"}
  },
  { _url = "http://dummy@example.com:1234/example.ext/another.php;k1=v1?k2=v2#k3=v3",
    _res = {
      scheme = "http",
      authority = "dummy@example.com:1234",
      userinfo = "dummy",
      user = "dummy",
      host = "example.com",
      port = 1234,
      path = "/example.ext/another.php",
      params = "k1=v1",
      query = "k2=v2",
      fragment = "k3=v3",
      is_folder = false,
      extension = "php",
    },
    _nil = {"password"}
  },
  { _url = "//example/example.folder/?k1=v1&k2=v2#k3/v3.bar",
    _res = {
      authority = "example",
      host = "example",
      path = "/example.folder/",
      query = "k1=v1&k2=v2",
      fragment = "k3/v3.bar",
      is_folder = true,
    },
    _nil = {"scheme", "userinfo", "port", "params", "extension"}
  },
}
for _, t in ipairs(test_urls) do
  local result = parse(t._url)
  for _, nv in ipairs(t._nil) do
    test_suite:add_test(unittest.is_nil(result[nv]), nv)
  end
  for k, v in pairs(t._res) do
    test_suite:add_test(unittest.equal(result[k], v), k)
  end
  test_suite:add_test(unittest.equal(build(t._res), t._url), "build test url")
  test_suite:add_test(unittest.equal(build(result), t._url), "parse/build round trip")
end


local parse_path_tests = {
  -- path, expected_tbl, expected_tbl_size
  {"/", {}, 0},
  {"//", {""}, 1},
  {"///", {"", ""}, 2},
  {"/test", {"test"}, 1},
  {"/test/", {"test"}, 1},
  {"/test//", {"test", ""}, 2},
  {"/test//test", {"test", "", "test"}, 3},
  {"/test//test/", {"test", "", "test"}, 3},
}

for test_k, test_v in ipairs(parse_path_tests) do
  local path, expected_tbl, expected_tbl_size = table.unpack(test_v)
  local parsed_path = parse_path(path)

  local parsed_path_size = 0
  for expected_k, expected_v in pairs(expected_tbl) do
    test_suite:add_test(
      unittest.equal(parsed_path[expected_k], expected_v),
      ("parse_path #%d `%q` - tbl key `%q`"):format(test_k, path, expected_k)
    )
    parsed_path_size = parsed_path_size + 1
  end
  test_suite:add_test(
    unittest.equal(parsed_path_size, expected_tbl_size),
    ("parse_path #%d `%q` - tbl size"):format(test_k, path)
  )
end

-- path merging tests for compliance with RFC 3986, section 5.2
-- https://tools.ietf.org/html/rfc3986#section-5.2
local absolute_path_tests = { -- {bpath, rpath, expected}
                             {'a',     '.',      ''    },
                             {'a',     './',     ''    },
                             {'..',    'b',      'b'   },
                             {'../',   'b',      'b'   },
                             {'/',     '..',     '/'   },
                             {'/',     '../',    '/'   },
                             {'/../',  '..',     '/'   },
                             {'/../',  '../',    '/'   },
                             {'a/..',  'b',      'b'   },
                             {'a/../', 'b',      'b'   },
                             {'/a/..', '',       '/'   },
                             {'',      '/a/..',  '/'   },
                             {'',      '/a//..', '/a/' },
                            }
for k, v in ipairs(absolute_path_tests) do
  local bpath, rpath, expected = table.unpack(v)
  test_suite:add_test(unittest.equal(absolute_path(bpath, rpath), expected),
                      ("absolute_path #%d (%q,%q)"):format(k, bpath, rpath))
end

return _ENV;
