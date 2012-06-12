local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves system information (OS version, available memory, etc.) from
a listening Ganglia Monitoring Daemon or Ganglia Meta Daemon.

Ganglia is a scalable distributed monitoring system for high-performance
computing systems such as clusters and Grids. The information retrieved
includes HDD size, available memory, OS version, architecture (and more) from
each of the systems in each of the clusters in the grid.

For more information about Ganglia, see:
* http://ganglia.sourceforge.net/
* http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Monitoring_Daemon_.28gmond.29
* http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Meta_Daemon_.28gmetad.29
]]

---
-- @usage
-- nmap --script ganglia-info --script-args ganglia-info.timeout=60,ganglia-info.bytes=1000000 -p <port> <target>
--
-- @args ganglia-info.timeout
--		   Set the timeout in seconds. The default value is 60.
--		   This should be enough for a grid of more than 100 hosts at 200Kb/s.
--		   About 5KB-10KB of data is returned for each host in the cluster.
-- @args ganglia-info.bytes
--		   Set the number of bytes to retrieve. The default value is 1000000.
--		   This should be enough for a grid of more than 100 hosts.
--		   About 5KB-10KB of data is returned for each host in the cluster.
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 8649/tcp open  ganglia Ganglia XML Grid monitor 2.5.7 (Cluster name: unspecified; Owner: unspecified; Source: gmond)
-- | ganglia-info:
-- |   Service: Ganglia Monitoring Daemon
-- |   Version: 2.5.7
-- |   Cluster Name: unspecified
-- |       Owner: unspecified
-- |       Hostname: localhost
-- |               IP: 127.0.0.1
-- |               cpu nice: 0.0%
-- |               cpu user: 2.0%
-- |               proc total: 182
-- |               proc run: 0
-- |               load fifteen: 0.13
-- |               pkts in: 0.12packets/sec
-- |               swap total: 9928700KB
-- |               load five: 0.15
-- |               machine type: x86_64
-- |               disk total: 236.111GB
-- |               mem buffers: 33148KB
-- |               mem total: 3845028KB
-- |               bytes in: 6.57bytes/sec
-- |               load one: 0.22
-- |               sys clock: 1317692483s
-- |               mem free: 3280956KB
-- |               mtu: 1280B
-- |               mem shared: 0KB
-- |               cpu aidle: 97.0%
-- |               cpu idle: 99.1%
-- |               cpu speed: 2266MHz
-- |               mem cached: 271924KB
-- |               cpu num: 4
-- |               part max used: 55.9%
-- |               bytes out: 5.48bytes/sec
-- |               os release: 2.6.34
-- |               gexec: OFF
-- |               disk free: 104.075GB
-- |               cpu system: 0.1%
-- |               boottime: 1317692167s
-- |               swap free: 9928700KB
-- |               os name: Linux
-- |_              pkts out: 0.06packets/sec

-- Version 0.1
-- Created 2011-06-28 - v0.1 - created by Brendan Coles - itsecuritysolutions.org

author = "Brendan Coles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service ({8649,8651}, "ganglia", {"tcp"})

action = function( host, port )

	local result = {}

	-- Set timeout
	local timeout = nmap.registry.args[SCRIPT_NAME .. '.timeout']
	if not timeout then
		timeout = 30
	else
		tonumber(timeout)
	end

	-- Set bytes
	local bytes = nmap.registry.args[SCRIPT_NAME .. '.bytes']
	if not bytes then
		bytes = 1000000
	else
		tonumber(bytes)
	end

	-- Retrieve grid data in XML format over TCP
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	local status, data = comm.get_banner(host, port, {timeout=timeout*1000,bytes=bytes})
	if not status then
		stdnse.print_debug(1, ("%s: Timeout exceeded for %s:%s (Timeout: %ss)."):format(SCRIPT_NAME, host.targetname or host.ip, port.number, timeout))
		return
	end

	-- Parse daemon info
	if not string.match(data, "<!DOCTYPE GANGLIA_XML") then
		stdnse.print_debug(1, ("%s: %s:%s is not a Ganglia Daemon."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	elseif string.match(data, '<GANGLIA_XML VERSION="([^"]*)" SOURCE="gmond"') then
		table.insert(result, "Service: Ganglia Monitoring Daemon")
		local version = string.match(data, '<GANGLIA_XML VERSION="([^"]*)" SOURCE="gmond"')
		if version then table.insert(result, string.format("Version: %s\n", version)) end
	elseif string.match(data, '<GANGLIA_XML VERSION="([^"]*)" SOURCE="gmetad"') then
		table.insert(result, "Service: Ganglia Meta Daemon")
		local version = string.match(data, '<GANGLIA_XML VERSION="([^"]*)" SOURCE="gmetad"')
		if version then table.insert(result, string.format("Version: %s\n", version)) end
		local grid = string.match(data, '<GRID NAME="([^"]*)" ')
		if grid then table.insert(result, string.format("Grid Name: %s", grid)) end
	else
		stdnse.print_debug(1, ("%s: %s:%s did not supply Ganglia daemon details."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Extract cluster details and system details for each cluster in the grid
	for line in string.gmatch(data, "[^\n]+") do
		if string.match(line, '<CLUSTER NAME="([^"]*)" ') and string.match(line, '<CLUSTER [^>]+ OWNER="([^"]*)" ') then
			table.insert(result, string.format("Cluster Name: %s\n\tOwner: %s\n", string.match(line, '<CLUSTER NAME="([^"]*)" '), string.match(line, '<CLUSTER [^>]+ OWNER="([^"]*)" ')))
		elseif string.match(line, '<HOST NAME="([^"]*)" IP="([^"]*)"') then
			table.insert(result, string.format("\tHostname: %s\n\t\tIP: %s\n", string.match(line, '<HOST NAME="([^"]*)" IP="[^"]*"'), string.match(line, '<HOST NAME="[^"]*" IP="([^"]*)"')))
		elseif string.match(line, '<METRIC NAME="([^"]*)" VAL="[^"]*" [^>]+ UNITS="[^"]*"') then
			table.insert(result, string.format("\t\t%s: %s%s", string.gsub(string.match(line, '<METRIC NAME="([^"]*)" VAL="[^"]*" [^>]+ UNITS="[^"]*"'), "_", " "), string.match(line, '<METRIC NAME="[^"]*" VAL="([^"]*)" [^>]+ UNITS="[^"]*"'), string.match(line, '<METRIC NAME="[^"]*" VAL="[^"]*" [^>]+ UNITS="([^"]*)"')))
		end
	end

	-- Return results
	return stdnse.format_output(true, result)

end
