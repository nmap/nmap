local coroutine = require "coroutine"
local mssql = require "mssql"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries the Microsoft SQL Browser service for the DAC (Dedicated Admin
Connection) port of a given (or all) SQL Server instance. The DAC port
is used to connect to the database instance when normal connection
attempts fail, for example, when server is hanging, out of memory or
in other bad states. In addition, the DAC port provides an admin with
access to system objects otherwise not accessible over normal
connections.

The DAC feature is accessible on the loopback adapter per default, but
can be activated for remote access by setting the 'remote admin
connection' configuration value to 1. In some cases, when DAC has been
remotely enabled but later disabled, the sql browser service may
incorrectly report it as available. The script therefore attempts to
connect to the reported port in order to verify whether it's
accessible or not.
]]

---
-- @usage
-- sudo nmap -sU -p 1434 --script ms-sql-dac <ip>
--
-- @output
-- | ms-sql-dac: 
-- |_  Instance: SQLSERVER; DAC port: 1533
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

hostrule = function(host)
	if ( mssql.Helper.WasDiscoveryPerformed( host ) ) then
		return mssql.Helper.GetDiscoveredInstances( host ) ~= nil
	else
		local sqlBrowserPort = nmap.get_port_state( host, {number = 1434, protocol = "udp"} )
		if ( (stdnse.get_script_args( {"mssql.instance-all", "mssql.instance-name", "mssql.instance-port"} ) ~= nil) or
				(sqlBrowserPort and (sqlBrowserPort.state == "open" or sqlBrowserPort.state == "open|filtered")) ) then
			return true
		end
	end
end

local function checkPort(host, port)
	local s = nmap.new_socket()
	s:set_timeout(5000)
	local status = s:connect(host, port, "tcp")
	s:close()
	return status
end

local function discoverDAC(host, name, result)
	local condvar = nmap.condvar(result)
	stdnse.print_debug(2, "Discovering DAC port on instance: %s", name)
	local port = mssql.Helper.DiscoverDACPort( host, name )
	if ( port ) then
		if ( checkPort(host, port) ) then
			table.insert(result, ("Instance: %s; DAC port: %s"):format(name, port))
		else
			table.insert(result, ("Instance: %s; DAC port: %s (connection failed)"):format(name, port))
		end
	end
	condvar "signal"
end

action = function( host )
	local result, threads = {}, {}
	local condvar = nmap.condvar(result)
	
	local status, instanceList = mssql.Helper.GetTargetInstances( host )
	-- if no instances were targeted, then display info on all
	if ( not status ) then
		if ( not mssql.Helper.WasDiscoveryPerformed( host ) ) then
			mssql.Helper.Discover( host )
		end
		instanceList = mssql.Helper.GetDiscoveredInstances( host )
	end
	
	for _, instance in ipairs(instanceList or {}) do
		local name = instance:GetName():match("^[^\\]*\\(.*)$")
		if ( name ) then
			local co = stdnse.new_thread(discoverDAC, host, name, result)
			threads[co] = true
		end
	end

	while(next(threads)) do
		for t in pairs(threads) do
			threads[t] = ( coroutine.status(t) ~= "dead" ) and true or nil
		end
		if ( next(threads) ) then
			condvar "wait"
		end
	end
	
	return stdnse.format_output( true, result )
end

