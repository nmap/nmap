description = [[
Calls <code>getinfo</code> on Bitcoin daemon's JSON-RPC interface.
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

require 'http'
require 'shortport'
require 'json'
require 'creds'

portrule = shortport.port_or_service(8332, "http")

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
			return self:call(method, arg)
		end
	end
	return o
end

function ServiceProxy:remote(req)
	local httpdata = http.post(self.host, self.port, self.path, self.options, nil, req)
	if stdnse.strsplit(" ", httpdata["status-line"])[2] ~= "200" then
		return
	end
	local body = httpdata["body"]
	return body
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
	local info = bitcoind.getinfo()
	if not info then
		return nil
	end
	local result = formatpairs(info)
	result["name"] = "USER: " .. user
	return result
end

action = function(host, port)
	local response = {}
	local c = creds.Credentials:new(creds.ALL_DATA, host, port)
	local states = creds.State.VALID + creds.State.PARAM
	for cred in c:getCredentials(states) do
		local info = getinfo(host, port, cred.user, cred.pass)
		table.insert(response, info)
	end
	return stdnse.format_output(true, response)
end

