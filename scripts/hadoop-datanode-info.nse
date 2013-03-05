local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Discovers information such as log directories from an Apache Hadoop DataNode HTTP status page.

Information gathered:
 * Log directory (relative to http://host:port/)

For more information about hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/DataNode
]]

---
-- @usage
-- nmap --script hadoop-datanode-info.nse -p 50075 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 50075/tcp open  hadoop-datanode syn-ack
-- | hadoop-datanode-info:
-- |_  Logs: /logs/
---


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service({50075}, "hadoop-datanode")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

	local result = {}
	local uri = "/browseDirectory.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		 if body:match("([^][\"]+)\">Log") then
			port.version.name = "hadoop-datanode"
			port.version.product = "Apache Hadoop"
			nmap.set_port_version(host, port)
			local logs = body:match("([^][\"]+)\">Log")
			stdnse.print_debug(1, ("%s: Logs %s"):format(SCRIPT_NAME,logs))
			table.insert(result, ("Logs: %s"):format(logs))
		end
		return stdnse.format_output(true, result)
	end
end
