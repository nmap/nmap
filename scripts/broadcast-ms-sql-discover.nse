description = [[
Discovers Microsoft SQL servers in the same broadcast domain.
]]

--
-- Version 0.1
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast"}

require 'mssql'
require 'target'

prerule = function() return true end

action = function()

	local OUTPUT_TBL = {
		["Server name"] = "info.servername",
		["Version"] = "version.version",
		["Clustered"] = "info.clustered",
		["Named pipe"] = "info.pipe",
		["Tcp port"] = "info.port"
	}
	
	local status, result = mssql.Helper.Discover("255.255.255.255", 1434, true)
	if ( not(status) ) then return end

	local results = {}
	for ip, instances in pairs(result) do
		local result_part = {}
		if target.ALLOW_NEW_TARGETS then target.add(ip)	end
		for name, info in pairs(instances) do
			local instance = {}
			local version
			status, version = mssql.Util.DecodeBrowserInfoVersion(info)
			
			for topic, varname in pairs(OUTPUT_TBL) do
				local func = loadstring( "return " .. varname )
				setfenv(func, setmetatable({ info=info; version=version; }, {__index = _G}))
				local result = func()
				if ( result ) then
					table.insert( instance, ("%s: %s"):format(topic, result) )
				end
			end
			instance.name = version.product
			table.insert( result_part, { name = "Instance: " .. info.name, instance } )
		end
		result_part.name = ip
		table.insert( results, result_part )
	end
	return stdnse.format_output( true, results )
end
