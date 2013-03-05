local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache HBase (Hadoop database) master HTTP status page.

Information gathered:
 * Hbase version
 * Hbase compile date
 * Hbase root eirectory
 * Hadoop version
 * Hadoop compile date
 * Average load
 * Zookeeper quorum server
 * Associated region servers

For more information about Hbase, see:
 * http://hbase.apache.org/
 * http://wiki.apache.org/hadoop/Hbase
 * http://wiki.apache.org/hadoop/TaskTracker
]]

---
-- @usage
-- nmap --script hbase-master-info -p 60010 host
--
-- @output
-- | hbase-master-info:
-- |   Hbase Version: 0.90.1
-- |   Hbase Compiled: Wed May 11 22:33:44 PDT 2011, bob
-- |   HBase Root Directory: hdfs://master.example.com:8020/hbase
-- |   Hadoop Version: 0.20  f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Hadoop Compiled: Wed May 11 22:33:44 PDT 2011, bob
-- |   Average Load: 0.12
-- |   Zookeeper Quorum: zookeeper.example.com:2181
-- |   Region Servers:
-- |     region1.example.com:60030
-- |_    region2.example.com:60030
---


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({60010}, "hbase-master")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

	local result = {}
	local region_servers = {}
	local uri = "/master.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		if body:match("HBase%s+Version</td><td>([^][<]+)") then
			local version = body:match("HBase%s+Version</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s:Hbase  Version %s"):format(SCRIPT_NAME,version))
			table.insert(result, ("Hbase Version: %s"):format(version))
			port.version.version = version
		end
		if body:match("HBase%s+Compiled</td><td>([^][<]+)") then
			local compiled = body:match("HBase%s+Compiled</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Hbase Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Hbase Compiled: %s"):format(compiled))
		end
		if body:match("Directory</td><td>([^][<]+)") then
			local compiled = body:match("Directory</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: HBase RootDirectory %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("HBase Root Directory: %s"):format(compiled))
		end
		if body:match("Hadoop%s+Version</td><td>([^][<]+)") then
			local version = body:match("Hadoop%s+Version</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Hadoop Version %s"):format(SCRIPT_NAME,version))
			table.insert(result, ("Hadoop Version: %s"):format(version))
		end
		if body:match("Hadoop%s+Compiled</td><td>([^][<]+)") then
			local compiled = body:match("Hadoop%s+Compiled</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Hadoop Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Hadoop Compiled: %s"):format(compiled))
		end
		if body:match("average</td><td>([^][<]+)") then
			local average = body:match("average</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Average Load %s"):format(SCRIPT_NAME,average))
			table.insert(result, ("Average Load: %s"):format(average))
		end
		if body:match("Quorum</td><td>([^][<]+)") then
			local quorum = body:match("Quorum</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Zookeeper Quorum %s"):format(SCRIPT_NAME,quorum))
			table.insert(result, ("Zookeeper Quorum: %s"):format(quorum))
			if target.ALLOW_NEW_TARGETS then
				if quorum:match("([%w%.]+)") then
					local newtarget = quorum:match("([%w%.]+)")
					stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
					local status,err = target.add(newtarget)
				 end
			end
		end
		for line in string.gmatch(body, "[^\n]+") do
			stdnse.print_debug(3, ("%s: Line %s\n"):format(SCRIPT_NAME,line))
			if line:match("maxHeap") then
				local region_server=  line:match("\">([^][<]+)</a>")
				stdnse.print_debug(1, ("%s: Region Server %s"):format(SCRIPT_NAME,region_server))
				table.insert(region_servers, region_server)
				if target.ALLOW_NEW_TARGETS then
					if region_server:match("([%w%.]+)") then
						local newtarget = region_server:match("([%w%.]+)")
						stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
						local status,err = target.add(newtarget)
					end
				end
			end
		end
		if next(region_servers) then
			table.insert(result,"Region Servers:")
			table.insert(result,region_servers)
		end
		if #result > 0 then
			port.version.name = "hbase-master"
			port.version.product = "Apache Hadoop Hbase"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
