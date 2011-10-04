description = [[
Retrieves system information from a listening Ganglia Monitoring Daemon or 
Ganglia Meta Daemon. Ganglia is a scalable distributed monitoring system for 
high-performance computing systems such as clusters and Grids. The information 
retrieved includes HDD size, available memory, OS version, architecture (and 
more) from each of the systems in each of the clusters in the grid.

For more information about Ganglia, see:
http://ganglia.sourceforge.net/
http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Monitoring_Daemon_.28gmond.29
http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Meta_Daemon_.28gmetad.29
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
-- PORT     STATE SERVICE REASON  VERSION
-- 8651/tcp open  ganglia syn-ack Ganglia XML Grid monitor 3.0.7 (Cluster name: Fyodor's Cluster 2; Owner: Fyodor; Source: gmetad)
-- | ganglia-info: 
-- |		Service: Ganglia Meta Daemon
-- |		Version: 3.0.7
-- |		Grid Name: Fyodor's Grid
-- |		Cluster Name: Fyodor's Cluster 1
-- |			Owner: Fyodor
-- |		Cluster Name: Fyodor's Cluster 2
-- |			Owner: Fyodor
-- |			Hostname: ganglia.example.com
-- |				IP: 192.168.1.1
-- |				disk total: 482.853GB
-- |				cpu speed: 2133MHz
-- |				part max used: 74.7%
-- |				swap total: 2097144KB
-- |				os name: Linux
-- |				cpu user: 3.4%
-- |				cpu system: 0.4%
-- |				cpu aidle: 95.2%
-- |				load five: 0.13 
-- |				proc run: 0 
-- |				mem free: 714040KB
-- |				mem buffers: 262100KB
-- |				swap free: 2097144KB
-- |				bytes in: 2332.70bytes/sec
-- |				pkts out: 2.70packets/sec
-- |				cpu num: 2CPUs
-- |				disk free: 188.861GB
-- |				mem total: 3114872KB
-- |				cpu wio: 0.1%
-- |				boottime: 1307115184s
-- |				machine type: x86
-- |				os release: 2.6.18-238.9.1.el5
-- |				cpu nice: 0.0%
-- |				cpu idle: 96.1%
-- |				load one: 0.04 
-- |				load fifteen: 0.14 
-- |				proc total: 245 
-- |				mem shared: 0KB
-- |				mem cached: 1260100KB
-- |				gexec: OFF
-- |				bytes out: 640.10bytes/sec
-- |_				pkts in: 12.90packets/sec

-- Version 0.1
-- Created 2011-06-28 - v0.1 - created by Brendan Coles <bcoles@gmail.com>

author = "Brendan Coles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require("comm")
require("shortport")

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
	if not string.match(data, "<\!DOCTYPE GANGLIA_XML") then
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
