local creds = require "creds"
local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Obtains information from a Bitcoin server by calling <code>getinfo</code> on its JSON-RPC interface.
]]

---
-- @usage
-- nmap -p 8332 --script bitcoinrpc-info --script-args creds.global=<user>:<pass> <target>
-- @args creds.global http credentials used for the query (user:pass)
-- @output
-- 8332/tcp open  unknown
-- | bitcoinrpc-info.nse:
-- |   root:
-- |     balance: 0
-- |     blocks: 135041
-- |     connections: 36
-- |     difficulty: 1379223.4296725
-- |     generate: false
-- |     genproclimit: -1
-- |     hashespersec: 0
-- |     keypoololdest: 1309381827
-- |     paytxfee: 0
-- |     testnet: false
-- |_    version: 32100
--
-- @xmloutput
-- <table key="root">
--   <elem key="balance">0</elem>
--   <elem key="blocks">135041</elem>
--   <elem key="connections">36</elem>
--   <elem key="difficulty">1379223.4296725</elem>
--   <elem key="generate">false</elem>
--   <elem key="genproclimit">-1</elem>
--   <elem key="hashespersec">0</elem>
--   <elem key="keypoololdest">1309381827</elem>
--   <elem key="paytxfee">0</elem>
--   <elem key="testnet">false</elem>
--   <elem key="version">32100</elem>
-- </table>

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"http-brute"}


portrule = shortport.portnumber(8332)

-- JSON-RPC helpers

local function request(method, params, id)
  json.make_array(params)
  local req = {method = method, params = params, id = id}
  local serial = json.generate(req)
  return serial
end

local function response(serial)
  local _, response = json.parse(serial)
  local result = response["result"]
  return result
end

local ServiceProxy = {}
function ServiceProxy:new(host, port, path, options)
  local o = {}
  setmetatable(o, self)
  self.host = host
  self.port = port
  self.path = path
  self.options = options
  self.__index = function(_, method)
    return function(...)
      return self:call(method, table.pack(...))
    end
  end
  return o
end

function ServiceProxy:remote(req)
  local httpdata = http.post(self.host, self.port, self.path, self.options, nil, req)
  if httpdata.status == 200 then
    return httpdata.body
  end
end

function ServiceProxy:call(method, args)
  local FIRST = 1
  local req = request(method, args, FIRST)
  local ret = self:remote(req)
  if not ret then
    return
  end
  local result = response(ret)
  return result
end

-- Convert an integer into a broken-down version number.
-- Prior to version 0.3.13, versions are 3-digit numbers as so:
--   200 -> 0.2.0
--   300 -> 0.3.0
--   310 -> 0.3.10
-- In 0.3.13 and later, they are 5-digit numbers as so:
--   31300 -> 0.3.13
--   31900 -> 0.3.19
-- Version 0.3.13 release announcement: https://bitcointalk.org/?topic=1327.0
local function decode_bitcoin_version(n)
  if n < 31300 then
    local minor, micro = n // 100, n % 100
    return string.format("0.%d.%d", minor, micro)
  else
    local minor, micro = n // 10000, (n // 100) % 100
    return string.format("0.%d.%d", minor, micro)
  end
end

local function formatpairs(info)
  local result = stdnse.output_table()
  local keys = stdnse.keys(info)
  table.sort(keys)
  for _, k in ipairs(keys) do
    if info[k] ~= "" then
      result[k] = info[k]
    end
  end
  return result
end

local function getinfo(host, port, user, pass)
  local auth = {username = user, password = pass}
  local bitcoind = ServiceProxy:new(host, port, "/", {auth = auth})
  return bitcoind.getinfo()
end

action = function(host, port)
  local response = stdnse.output_table()
  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  local states = creds.State.VALID + creds.State.PARAM
  for cred in c:getCredentials(states) do
    local info = getinfo(host, port, cred.user, cred.pass)
    if info then
      local result = formatpairs(info)
      response[cred.user] = result

      port.version.name = "http"
      port.version.product = "Bitcoin JSON-RPC"
      if info.version then
        port.version.version = decode_bitcoin_version(info.version)
      end
      nmap.set_port_version(host, port)
    end
  end

  return response
end

