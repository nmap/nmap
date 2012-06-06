local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Tests an http server for Cross-Origin Resource Sharing (CORS), a way
for domains to explicitly opt in to having certain methods invoked by
another domain.

The script works by setting the Access-Control-Request-Method header
field for certain enumerated methods in OPTIONS requests, and checking
the responses.
]]

---
-- @args http-cors.path The path to request. Defaults to
-- <code>/</code>.
--
-- @args http-cors.origin The origin used with requests. Defaults to
-- <code>example.com</code>.
--
-- @usage
-- nmap -p 80 --script http-cors <target>
--
-- @output
-- 80/tcp open
-- |_cors.nse: GET POST OPTIONS


author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule =  shortport.http

local methods = {"HEAD", "GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"}

local function origin_ok(raw, origin)
	if not raw then
		return false
	end
	if raw == "*" then
		return true
	end
	if raw == "null" then
		return false
	end
	local allowed = stdnse.strsplit(" ", raw)
	for _, ao in ipairs(allowed) do
		if origin == ao then
			return true
		end
	end
	return false
end

local function method_ok(raw, method)
	if not raw then
		return false
	end
	local stuff = stdnse.strsplit(" ", raw)
	local nospace = stdnse.strjoin("", stuff)
	local allowed = stdnse.strsplit(",", nospace)
	for _, am in ipairs(allowed) do
		if method == am then
			return true
		end
	end
	return false
end

local function test(host, port, method, origin)
	local header = {
		["Origin"] = origin,
		["Access-Control-Request-Method"] = method,
	}
	local response = http.generic_request(host, port, "OPTIONS", "/", {header = header})
	local aorigins = response.header["access-control-allow-origin"]
	local amethods = response.header["access-control-allow-methods"]
	local ook = origin_ok(aorigins, response)
	local mok = method_ok(amethods, method)
	return ook and mok
end

action = function(host, port)
        local path = nmap.registry.args["http-cors.path"] or "/"
	local origin =  nmap.registry.args["http-cors.origin"] or "example.com"
	local allowed = {}
	for _, method in ipairs(methods) do
		if test(host, port, method, origin) then
			table.insert(allowed, method)
		end
	end
	if #allowed > 0 then
		return stdnse.strjoin(" ", allowed)
	end
end
