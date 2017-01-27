local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Parses and displays the banner information of an OpenLookup (network key-value store) server.
]]

---
-- @usage
-- nmap -p 5850 --script openlookup-info <target>
--
-- @output
-- 5850/tcp open  openlookup
-- | openlookup-info:
-- |   sync port: 5850
-- |   name: Paradise, Arizona
-- |   your address: 127.0.0.1:50162
-- |   timestamp: 2011-05-21T11:26:07
-- |   version: 2.7
-- |_  http port: 5851
--
-- @xmloutput
-- <elem key="sync port">5850</elem>
-- <elem key="name">Paradise, Arizona</elem>
-- <elem key="your address">127.0.0.1:50162</elem>
-- <elem key="timestamp">2011-05-21T11:26:07</elem>
-- <elem key="version">2.7</elem>
-- <elem key="http port">5851</elem>

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe", "version"}


portrule = shortport.version_port_or_service(5850, "openlookup")

-- Netstring helpers
-- http://cr.yp.to/proto/netstrings.txt

-- parses a Netstring element
local function parsechunk(data)
  local parts = stdnse.strsplit(":", data)
  if #parts < 2 then
    return nil, data
  end
  local head = table.remove(parts, 1)
  local size = tonumber(head)
  if not size then
    return nil, data
  end
  local body = stdnse.strjoin(":", parts)
  if #body < size then
    return nil, data
  end
  local chunk = string.sub(body, 1, size)
  local skip = #chunk + string.len(",")
  local rest = string.sub(body, skip + 1)
  return chunk, rest
end

-- NSON helpers
-- http://code.google.com/p/messkit/source/browse/trunk/messkit/nson.py

-- parses an NSON int
local function parseint(data)
  if string.sub(data, 1, 1) ~= "i" then
    return
  end
  local text = string.sub(data, 2)
  local number = tonumber(text)
  return number
end

-- parses an NSON float
local function parsefloat(data)
  if string.sub(data, 1, 1) ~= "f" then
    return
  end
  local text = string.sub(data, 2)
  local number = tonumber(text)
  return number
end

-- parses an NSON string
local function parsestring(data)
  if string.sub(data, 1, 1) ~= "s" then
    return
  end
  return string.sub(data, 2)
end

-- parses an NSON int, float, or string
local function parsesimple(data)
  local i = parseint(data)
  local f = parsefloat(data)
  local s = parsestring(data)
  return i or f or s
end

-- parses an NSON dictionary
local function parsedict(data)
  if #data < 1 then
    return
  end
  if string.sub(data, 1, 1) ~= "d" then
    return
  end
  local rest = string.sub(data, 2)
  local dict = {}
  while #rest > 0 do
    local chunk, key, value
    chunk, rest = parsechunk(rest)
    if not chunk then
      return
    end
    key = parsestring(chunk)
    value, rest = parsechunk(rest)
    if not value then
      return
    end
    dict[key] = value
  end
  return dict
end

-- parses an NSON array
local function parsearray(data)
  if #data < 1 then
    return
  end
  if string.sub(data, 1, 1) ~= "a" then
    return
  end
  local rest = string.sub(data, 2)
  local array = {}
  while #rest > 0 do
    local value
    value, rest = parsechunk(rest)
    if not value then
      return
    end
    table.insert(array, value)
  end
  return array
end

-- OpenLookup specific stuff

local function formataddress(data)
  local parts = parsearray(data)
  if not parts then
    return
  end
  if #parts < 2 then
    return
  end
  local ip = parsestring(parts[1])
  if not ip then
    return
  end
  local port = parseint(parts[2])
  if not port then
    return
  end
  return ip .. ":" .. port
end

local function formattime(data)
  local time = parsefloat(data)
  if not time then
    return
  end
  return stdnse.format_timestamp(time)
end

local function formatvalue(key, nson)
  local value
  if key == "your_address" then
    value = formataddress(nson)
  elseif key == "timestamp" then
    value = formattime(nson)
  else
    value = parsesimple(nson)
  end
  if not value then
    value = "<" .. #nson .. "B of data>"
  end
  return value
end

function formatoptions(header)
  local msg = parsedict(header)
  if not msg then
    return
  end
  local rawmeth = msg["method"]
  if not rawmeth then
    stdnse.debug2("header missing method field")
    return
  end
  local method = parsestring(rawmeth)
  if not method then
    return
  end
  if method ~= "hello" then
    stdnse.debug1("expecting hello, got " .. method .. " instead")
    return
  end
  local rawopts = msg["options"]
  if not rawopts then
    return {}
  end
  return parsedict(rawopts)
end

action = function(host, port)
  local status, banner = comm.get_banner(host, port)
  if not status then
    return
  end
  local header, _ = parsechunk(banner)
  if not header then
    return
  end
  local options = formatoptions(header)
  if not options then
    return
  end
  port.version.name = "openlookup"
  local version = options["version"]
  if version then
    port.version.version = version
  end
  nmap.set_port_version(host, port)
  if #options < 1 then
    return
  end
  return options
end

