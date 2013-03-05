local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache Hadoop NameNode HTTP status page.

Information gathered:
 * Date/time the service was started
 * Hadoop version
 * Hadoop compile date
 * Upgrades status
 * Filesystem directory (relative to http://host:port/)
 * Log directory (relative to http://host:port/)
 * Associated DataNodes.

For more information about Hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/NameNode
]]

---
-- @usage
-- nmap --script hadoop-namenode-info -p 50070 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 50070/tcp open  hadoop-namenode syn-ack
-- | hadoop-namenode-info:
-- |   Started:  Wed May 11 22:33:44 PDT 2011
-- |   Version:  0.20.2-cdh3u1, f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Compiled:  Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Upgrades:  There are no upgrades in progress.
-- |   Filesystem: /nn_browsedfscontent.jsp
-- |   Logs: /logs/
-- |   Storage:
-- |   Total       Used (DFS)      Used (Non DFS)  Remaining
-- |   100 TB      85 TB           500 GB          14.5 TB
-- |   Datanodes (Live):
-- |     Datanode: datanode1.example.com:50075
-- |     Datanode: datanode2.example.com:50075
---


author = "John R. Bond (john.r.bond@gmail.com)"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({50070}, "hadoop-namenode")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

get_datanodes = function( host, port, Status )
	local result = {}
	local uri = "/dfsnodelist.jsp?whatNodes=" .. Status
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response" ))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		for datanodetmp in string.gmatch(body, "[%w%.:-_]+/browseDirectory.jsp") do
			local datanode = datanodetmp:gsub("/browseDirectory.jsp","")
			stdnse.print_debug(1, ("%s: Datanode %s"):format(SCRIPT_NAME,datanode))
			table.insert(result, ("Datanode: %s"):format(datanode))
			if target.ALLOW_NEW_TARGETS then
				if datanode:match("([%w%.]+)") then
					local newtarget = datanode:match("([%w%.]+)")
					stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
					local status,err = target.add(newtarget)
				end
			end
		end
	end
	return result
end

action = function( host, port )

	local result = {}
	local uri = "/dfshealth.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		local capacity = {}
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		if body:match("Started:%s*<td>([^][<]+)") then
			local start = body:match("Started:%s*<td>([^][<]+)")
			stdnse.print_debug(1, ("%s: Started %s"):format(SCRIPT_NAME,start))
			table.insert(result, ("Started: %s"):format(start))
		end
		if body:match("Version:%s*<td>([^][<]+)") then
			local version = body:match("Version:%s*<td>([^][<]+)")
			stdnse.print_debug(1, ("%s: Version %s"):format(SCRIPT_NAME,version))
			table.insert(result, ("Version: %s"):format(version))
			port.version.version = version
		end
		if body:match("Compiled:%s*<td>([^][<]+)") then
			local compiled = body:match("Compiled:%s*<td>([^][<]+)")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Compiled: %s"):format(compiled))
		end
		if body:match("Upgrades:%s*<td>([^][<]+)") then
			local upgrades = body:match("Upgrades:%s*<td>([^][<]+)")
			stdnse.print_debug(1, ("%s: Upgrades %s"):format(SCRIPT_NAME,upgrades))
			table.insert(result, ("Upgrades: %s"):format(upgrades))
		end
		if body:match("([^][\"]+)\">Browse") then
			local filesystem = body:match("([^][\"]+)\">Browse")
			stdnse.print_debug(1, ("%s: Filesystem %s"):format(SCRIPT_NAME,filesystem))
			table.insert(result, ("Filesystem: %s"):format(filesystem))
		end
		if body:match("([^][\"]+)\">Namenode") then
			local logs = body:match("([^][\"]+)\">Namenode")
			stdnse.print_debug(1, ("%s: Logs %s"):format(SCRIPT_NAME,logs))
			table.insert(result, ("Logs: %s"):format(logs))
		end
		for i in string.gmatch(body, "[%d%.]+%s[KMGTP]B") do
			table.insert(capacity,i)
		end
		if #capacity >= 6 then
			stdnse.print_debug(1, ("%s: Total %s"):format(SCRIPT_NAME,capacity[3]))
			stdnse.print_debug(1, ("%s: Used DFS (NonDFS) %s (%s)"):format(SCRIPT_NAME,capacity[4],capacity[5]))
			stdnse.print_debug(1, ("%s: Remaining %s"):format(SCRIPT_NAME,capacity[6]))
			table.insert(result,"Storage:")
			table.insert(result,"Total\tUsed (DFS)\tUsed (Non DFS)\tRemaining")
			table.insert(result, ("%s\t%s\t%s\t%s"):format(capacity[3],capacity[4],capacity[5],capacity[6]))
		end
		local datanodes_live = get_datanodes(host,port, "LIVE")
		if next(datanodes_live) then
			table.insert(result, "Datanodes (Live): ")
			table.insert(result, datanodes_live)
		end
		local datanodes_dead = get_datanodes(host,port, "DEAD")
		if next(datanodes_dead) then
			table.insert(result, "Datanodes (Dead): ")
			table.insert(result, datanodes_dead)
		end
		if #result > 0 then
			port.version.name = "hadoop-namenode"
			port.version.product = "Apache Hadoop"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
