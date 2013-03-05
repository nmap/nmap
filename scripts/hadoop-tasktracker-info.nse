local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves information from an Apache Hadoop TaskTracker HTTP status page.

Information gathered:
 * Hadoop version
 * Hadoop Compile date
 * Log directory (relative to http://host:port/)

For more information about Hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/TaskTracker
]]

---
-- @usage
-- nmap --script hadoop-tasktracker-info -p 50060 host
--
-- @output
-- PORT      STATE SERVICE            REASON
-- 50060/tcp open  hadoop-tasktracker syn-ack
-- | hadoop-tasktracker-info:
-- |   Version: 0.20.1 (f415ef415ef415ef415ef415ef415ef415ef415e)
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |_  Logs: /logs/
---


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({50060}, "hadoop-tasktracker")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

	local result = {}
	local uri = "/tasktracker.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		if response['body']:match("Version:</b>%s*([^][<]+)") then
			local version = response['body']:match("Version:</b>%s*([^][<]+)")
			local versionNo = version:match("([^][,]+)")
			local versionHash = version:match("[^][,]+%s+(%w+)")
			stdnse.print_debug(1, ("%s: Version %s (%s)"):format(SCRIPT_NAME,versionNo,versionHash))
			table.insert(result, ("Version: %s (%s)"):format(versionNo,versionHash))
			port.version.version = version
		end
		if response['body']:match("Compiled:</b>%s*([^][<]+)") then
			local compiled = response['body']:match("Compiled:</b>%s*([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Compiled: %s"):format(compiled))
		end
		if body:match("([^][\"]+)\">Log") then
			local logs = body:match("([^][\"]+)\">Log")
			stdnse.print_debug(1, ("%s: Logs %s"):format(SCRIPT_NAME,logs))
			table.insert(result, ("Logs: %s"):format(logs))
		end
		if #result > 0 then
			port.version.name = "hadoop-tasktracker"
			port.version.product = "Apache Hadoop"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
