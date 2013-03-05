local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache Hadoop JobTracker HTTP status page.

Information gathered:
 * State of the JobTracker.
 * Date/time the service was started
 * Hadoop version
 * Hadoop Compile date
 * JobTracker ID
 * Log directory (relative to http://host:port/)
 * Associated TaskTrackers
 * Optionally also user activity history

For more information about Hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/JobTracker
]]

---
-- @usage
-- nmap --script hadoop-jobtracker-info [--script-args=hadoop-jobtracker-info.userinfo] -p 50030 host
--
-- @output
-- 50030/tcp open  hadoop-jobtracker
-- | hadoop-jobtracker-info:
-- |   State: RUNNING
-- |   Started: Wed May 11 22:33:44 PDT 2011, bob
-- |   Version: 0.20.2 (f415ef415ef415ef415ef415ef415ef415ef415e)
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Identifier: 201111031342
-- |   Log Files: logs/
-- |   Tasktrackers:
-- |     tracker1.example.com:50060
-- |    tracker2.example.com:50060
-- |   Userhistory:
-- |     User: bob (Wed Sep 07 12:14:33 CEST 2011)
-- |_    User: bob (Wed Sep 07 12:14:33 CEST 2011)
-- ---


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({50030}, "hadoop-jobtracker")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

get_userhistory = function( host, port )
	local results = {}
	local uri = "/jobhistory.jsp?pageno=-1&search="
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		for line in string.gmatch(body, "[^\n]+") do
			stdnse.print_debug(3, ("%s: Line %s\n"):format(SCRIPT_NAME,line))
			if line:match("job_[%d_]+") then
				local user =  line:match("<td>([^][<>]+)</td></tr>")
				local job_time =  line:match("</td><td>([^][<]+)")
				stdnse.print_debug(1, ("%s: User: %s (%s)"):format(SCRIPT_NAME,user,job_time))
				table.insert( results,  ("User: %s (%s)"):format(user,job_time))
			end
		end
	end
	return results
end
get_tasktrackers = function( host, port )
	local results = {}
	local uri = "/machines.jsp?type=active"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,response['body']))
		for line in string.gmatch(response['body'], "[^\n]+") do
			stdnse.print_debug(3, ("%s: Line %s\n"):format(SCRIPT_NAME,line))
			if line:match("href=\"[%w]+://([%w%.:]+)/\">tracker") then
				local tasktracker =  line:match("href=\".*//([%w%.:]+)/\">tracker")
				stdnse.print_debug(1, ("%s: taskstracker %s"):format(SCRIPT_NAME,tasktracker))
				table.insert( results, tasktracker)
				if target.ALLOW_NEW_TARGETS then
					if tasktracker:match("([%w%.]+)") then
						local newtarget = tasktracker:match("([%w%.]+)")
						stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
						local status,err = target.add(newtarget)
					end
				end
			end
		end
	end
	return results
end
action = function( host, port )

	local result = {}
	local uri = "/jobtracker.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,response['body']))
		if response['body']:match("State:</b>%s*([^][<]+)") then
			local state = response['body']:match("State:</b>%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: State %s"):format(SCRIPT_NAME,state))
			table.insert(result, ("State: %s"):format(state))
		end
		if response['body']:match("Started:</b>%s*([^][<]+)") then
			local started = response['body']:match("Started:</b>%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: Started %s"):format(SCRIPT_NAME,started))
			table.insert(result, ("Started: %s"):format(started))
		end
		if response['body']:match("Version:</b>%s*([^][<]+)") then
			local version = response['body']:match("Version:</b>%s*([^][<]+)")
			local versionNo = version:match("([^][,]+)")
			local versionHash = version:match("[^][,]+%s+(%w+)")
			stdnse.print_debug(1, ("%s: Version %s (%s)"):format(SCRIPT_NAME,versionNo,versionHash))
			table.insert(result, ("Version: %s (%s)"):format(versionNo,versionHash))
			port.version.version = versionNo
		end
		if response['body']:match("Compiled:</b>%s*([^][<]+)") then
			local compiled = response['body']:match("Compiled:</b>%s*([^][<]+)"):gsub("%s+", " ")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Compiled: %s"):format(compiled))
		end
		if response['body']:match("Identifier:</b>%s*([^][<]+)") then
			local identifier = response['body']:match("Identifier:</b>%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: Identifier %s"):format(SCRIPT_NAME,identifier))
			table.insert(result, ("Identifier: %s"):format(identifier))
		end
		if response['body']:match("([%w/]+)\">Log<") then
			local logfiles = response['body']:match("([%w/-_:%%]+)\">Log<")
			stdnse.print_debug(1, ("%s: Log Files %s"):format(SCRIPT_NAME,logfiles))
			table.insert(result, ("Log Files: %s"):format(logfiles))
		end
		local tasktrackers = get_tasktrackers (host, port)
		if next(tasktrackers) then
			table.insert(result, "Tasktrackers: ")
			table.insert(result, tasktrackers)
		end
		if stdnse.get_script_args('hadoop-jobtracker-info.userinfo') then
			local userhistory = get_userhistory (host, port)
			table.insert(result, "Userhistory: ")
			table.insert(result, userhistory)
		end
		if #result > 0 then
			port.version.name = "hadoop-jobtracker"
			port.version.product = "Apache Hadoop"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
