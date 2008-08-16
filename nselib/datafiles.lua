-- Kris Katterjohn 03/2008

module(... or "datafiles", package.seeall)

require 'stdnse'

-- These tables are filled by the following fill* functions
local protocols_table = {}
local rpc_table = {}
local services_table = {tcp={}, udp={}}

-- Fills protocols or rpc table with values read from the nmap-* files
local filltable = function(filename, table)
	if #table ~= 0 then
		return true
	end

	local path = nmap.fetchfile(filename)

	if path == nil then
		return false
	end

	local file = io.open(path, "r")

	-- Loops through file line-by-line
	while true do
		local l = file:read()

		if not l then
			break
		end

		l = l:gsub("%s*#.*", "")

		if l:len() ~= 0 then
			local m = l:gsub("^([%a%d_-]+)%s+(%d+).*", "%2=%1")

			if m:match("=") then
				local t = stdnse.strsplit("=", m)
				table[tonumber(t[1])] = t[2]
			end
		end
	end

	file:close()

	return true
end

-- Fills services_table{} with values read from nmap-services
local fillservices = function()
	if #services_table["tcp"] ~= 0 or
	   #services_table["udp"] ~= 0 then
		return true
	end

	local path = nmap.fetchfile("nmap-services")

	if path == nil then
		return false
	end

	local file = io.open(path, "r")

	-- Loops through nmap-services line-by-line
	while true do
		local l = file:read()

		if not l then
			break
		end

		l = l:gsub("%s*#.*", "")

		if l:len() ~= 0 then
			local m = l:gsub("^([%a%d_-]+)%s+([%a%d/]+).*", "%2=%1")

			if m:match("=") and m:match("/") then
				local t = stdnse.strsplit("=", m)
				local s = stdnse.strsplit("/", t[1])

				if s[2] ~= "tcp" and s[2] ~= "udp" then
					services_table = {tcp={}, udp={}}
					return false
				end

				services_table[s[2]][tonumber(s[1])] = t[2]
			end
		end
	end

	file:close()

	return true
end

parse_protocols = function()
	if not filltable("nmap-protocols", protocols_table) then
		return false, "Error parsing nmap-protocols"
	end

	return true, protocols_table
end

parse_rpc = function()
	if not filltable("nmap-rpc", rpc_table) then
		return false, "Error parsing nmap-rpc"
	end

	return true, rpc_table
end

parse_services = function(protocol)
	if protocol and protocol ~= "tcp" and protocol ~= "udp" then
		return false, "Bad protocol for nmap-services: use tcp or udp"
	end

	if not fillservices() then
		return false, "Error parsing nmap-services"
	end

	if protocol then
		return true, services_table[protocol]
	end
	return true, services_table
end

