local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache HBase (Hadoop database) region server HTTP status page.

Information gathered:
 * HBase version
 * HBase compile date
 * A bunch of metrics about the state of the region server
 * Zookeeper quorum server

For more information about Hbase, see:
 * http://hbase.apache.org/
 * http://wiki.apache.org/hadoop/Hbase
]]

---
-- @usage
-- nmap --script hbase-region-info -p 60030 host
--
-- @output
-- PORT      STATE SERVICE      REASON
-- 60030/tcp open  hbase-region syn-ack
-- | hbase-region-info:
-- |   Hbase Version: 0.90.1
-- |   Hbase Compiled: Wed May 11 22:33:44 PDT 2011, bob
-- |   Metrics requests=0, regions=0, stores=0, storefiles=0, storefileIndexSize=0, memstoreSize=0,
-- |   compactionQueueSize=0, flushQueueSize=0, usedHeap=0, maxHeap=0, blockCacheSize=0,
-- |   blockCacheFree=0, blockCacheCount=0, blockCacheHitCount=0, blockCacheMissCount=0,
-- |   blockCacheEvictedCount=0, blockCacheHitRatio=0, blockCacheHitCachingRatio=0
-- |_  Zookeeper Quorum: zookeeper.example.com:2181
---


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({60030}, "hbase-region")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

	local result = {}
	local region_servers = {}
	-- uri was previously "/regionserver.jsp". See
	-- http://seclists.org/nmap-dev/2012/q3/903.
	local uri = "/rs-status"
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
		if body:match("Metrics</td><td>([^][<]+)") then
			local metrics = body:match("Metrics</td><td>([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Metrics %s"):format(SCRIPT_NAME,metrics))
			table.insert(result, ("Metrics %s"):format(metrics))
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
		if #result > 0 then
			port.version.name = "hbase-region"
			port.version.product = "Apache Hadoop Hbase"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
