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
-- |   USER: root
-- |     connections: 36
-- |     hashespersec: 0
-- |     generate: false
-- |     keypoololdest: 1309381827
-- |     difficulty: 1379223.4296725
-- |     balance: 0
-- |     version: 32100
-- |     paytxfee: 0
-- |     testnet: false
-- |     blocks: 135041
-- |_    genproclimit: -1

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
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
		local minor, micro = n / 100, n % 100
		return string.format("0.%d.%d", minor, micro)
	else
		local minor, micro = n / 10000, (n / 100) % 100
		return string.format("0.%d.%d", minor, micro)
	end
end

local function formatpairs(info)
	local result = {}
	for k, v in pairs(info) do
		if v ~= "" then
			local line = k .. ": " .. tostring(v)
			table.insert(result, line)
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
	local response = {}
	local c = creds.Credentials:new(creds.ALL_DATA, host, port)
	local states = creds.State.VALID + creds.State.PARAM
	for cred in c:getCredentials(states) do
		local info = getinfo(host, port, cred.user, cred.pass)
		if info then
			local result = formatpairs(info)
			result["name"] = "USER: " .. cred.user
			table.insert(response, result)

			port.version.name = "http"
			port.version.product = "Bitcoin JSON-RPC"
			if info.version then
				port.version.version = decode_bitcoin_version(info.version)
			end
			nmap.set_port_version(host, port)
		end
	end

	return stdnse.format_output(true, response)
end

