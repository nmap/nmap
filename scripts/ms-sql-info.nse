description = [[
Attempts to extract information from Microsoft SQL Server instances.
]]
-- rev 1.0 (2007-06-09)
-- rev 1.1 (2009-12-06 - Added SQL 2008 identification T Sellers)
-- rev 1.2 (2010-10-03 - Added Broadcast support <patrik@cqure.net>)
-- rev 1.3 (2010-10-10 - Added prerule and newtargets support <patrik@cqure.net>)

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "intrusive"}

---
-- @output
-- PORT     STATE SERVICE  REASON
-- 1434/udp open  ms-sql-m script-set
-- | ms-sql-info: Discovered Microsoft SQL Server 2008 Express Edition
-- |   Server name: MAC-MINI
-- |   Server version: 10.0.2531.0 (SP1)
-- |   Instance name: SQLEXPRESS
-- |   TCP Port: 1433
-- |_    Could not retrieve actual version information
--

require("shortport")
require("target")
require("mssql")

prerule = function() return false end
portrule = shortport.portnumber({1433, 1434}, "udp", {"open", "open|filtered"})


local parse_version = function(ver_str)

	local version = {}
	version.full = ver_str
	version.product_long = ver_str:match("(Microsoft.-)\n") or ""
	version.product = ver_str:match("^(Microsoft SQL Server %w-)%s") or ""
	version.edition = ver_str:match("\n.-\n.-\n%s*(.-%sEdition)%s") or ""
	version.edition_long = ver_str:match("\n.-\n.-\n%s*(.-Build.-)\n") or ""
	version.version = ver_str:match("^Microsoft.-%-.-([%.%d+]+)") or ""
	version.level   = ver_str:match("^Microsoft.-%((.+)%)%s%-") or ""
	version.windows = ver_str:match(" on%s(.*)\n$") or ""
	version.real = true
	
	return true, version
end

local function retrieve_version_as_user( info, user, pass )

	local helper, status
	local SQL_DB = "master"

	if ( info.servername and info.port ) then
		local hosts
		status, hosts = nmap.resolve(info.servername, nmap.address_family())
		
		if ( status ) then
			local err
			for _, host in ipairs( hosts ) do
				helper = mssql.Helper:new()
				status, err = helper:Connect(host, info.port)
				if ( status ) then break end
			end
			-- we failed to connect to all of the resolved hostnames,
			-- fall back to sql browser ip
			if ( not(status) ) then
				helper = mssql.Helper:new()
				status, err = helper:Connect( info.ip, info.port )
			end
		else
			-- resolve wasn't successful, fall back to browser service ip
			stdnse.print_debug(3, "ERROR: Failed to resolve the hostname %s", info.servername)
			helper = mssql.Helper:new()
			status, err = helper:Connect( info.ip, info.port )
		end
	else
		-- we're missing either the servername or the port
		return false, "ERROR: Either servername or tcp port is missing"
	end	
	
	if ( not(status) ) then return false, "ERROR: Failed to connect to server" end
	
	status, result = helper:Login( user, pass, SQL_DB, info.servername )
	if ( not(status) ) then
		stdnse.print_debug(3, "%s: login failed, reason: %s", SCRIPT_NAME, result )
		return status, "Could not retrieve actual version information"
	end

	local query = "SELECT @@version ver"
	status, result = helper:Query( query )
	if ( not(status) ) then
		stdnse.print_debug(3, "%s: query failed, reason: %s", SCRIPT_NAME, result )
		return status, "Could not retrieve actual version information"
	end

	helper:Disconnect()

	if ( result.rows ) then	return parse_version( result.rows[1][1] ) end
end

local function process_response( serverInfo )
	
	local SQL_USER, SQL_PASS = "sa", ""
	local TABLE_DATA = {
		["Server name"] = "info.servername",
		["Server version"] = "version.version",
		["Server edition"] = "version.edition_long",
		["Clustered"] = "info.clustered",
		["Named pipe"] = "info.pipe",
		["Tcp port"] = "info.port",
	}

	local result = {}
	
	for _, info in pairs(serverInfo) do
		local result_part = {}

		-- The browser service could point to instances on other IP's
		-- therefore the correct behavior should be to connect to the
		-- servername returned for the instance rather than the browser IP.
		-- In case this fails, due to name resolution or something else, fall
		-- back to the browser service IP.
		local status, version = retrieve_version_as_user(info, SQL_USER, SQL_PASS)
		
		if (status) then
			if ( version.edition ) then
				version.product = version.product .. " " .. version.edition
			end
			version.version = version.version .. (" (%s)"):format(version.level)
		else
			status, version = mssql.Util.DecodeBrowserInfoVersion(info)
		end

		-- format output
		for topic, varname in pairs(TABLE_DATA) do
			local func = loadstring( "return " .. varname )
			setfenv(func, setmetatable({ info=info; version=version; }, {__index = _G}))
			local result = func()
			if ( result ) then
				table.insert( result_part, ("%s: %s"):format(topic, result) )
			end
		end
		result_part.name = version.product
		
		if ( version.real ) then
			table.insert(result_part, "WARNING: Database was accessible as SA with empty password!")
		end
		
		table.insert(result, { name = "Instance: " .. info.name, result_part } )
	end
	return result
end


action = function( host, port )

	local status, response = mssql.Helper.Discover( host, port )
	if ( not(status) ) then return end

	local result, serverInfo = process_response( response[host.ip] )
	if ( not(result) ) then return end

	nmap.set_port_state( host, port, "open")
	return stdnse.format_output( true, result )
end


