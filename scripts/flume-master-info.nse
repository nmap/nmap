local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from Flume master HTTP pages.

Information gathered:
* Flume version
* Flume server id
* Zookeeper/Hbase master servers present in configured flows
* Java information
* OS information
* various other local configurations.

If this script is run wth -v, it will output lots more info.

Use the <code>newtargets</code> script argument to add discovered hosts to the
Namp scan queue.
]]

---
-- @usage
-- nmap --script flume-master-info -p 35871 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 35871/tcp open  flume-master syn-ack
--| flume-master-info: 
--|   Version:  0.9.4-cdh3u3
--|   ServerID: 0
--|   Flume nodes:
--|     node1.example.com
--|     node2.example.com
--|     node5.example.com
--|     node6.example.com
--|     node3.example.com
--|     node4.example.com
--|   Zookeeper Master:
--|     master1.example.com
--|   Hbase Master Master:
--|     hdfs://master1.example.com:8020/hbase
--|   Enviroment: 
--|     java.runtime.name: Java(TM) SE Runtime Environment
--|     java.runtime.version: 1.6.0_36-a01
--|     java.version: 1.6.0_36
--|     java.vm.name: Java HotSpot(TM) 64-Bit Server VM
--|     java.vm.vendor: Sun Microsystems Inc.
--|     java.vm.version: 14.0-b12
--|     os.arch: amd64
--|     os.name: Linux
--|     os.version: 2.6.32-220.4.2.el6.x86_64
--|     user.country: US
--|     user.name: flume
--|   Config: 
--|     dfs.datanode.address: 0.0.0.0:50010
--|     dfs.datanode.http.address: 0.0.0.0:50075
--|     dfs.datanode.https.address: 0.0.0.0:50475
--|     dfs.datanode.ipc.address: 0.0.0.0:50020
--|     dfs.http.address: master1.example.com:50070
--|     dfs.https.address: 0.0.0.0:50470
--|     dfs.secondary.http.address: 0.0.0.0:50090
--|     flume.collector.dfs.dir: hdfs://master1.example.com/user/flume/collected
--|     flume.collector.event.host: node1.example.com
--|     flume.master.servers: master1.example.com
--|     fs.default.name: hdfs://master1.example.com:8020
--|     mapred.job.tracker: master1.example.com:9001
--|     mapred.job.tracker.handler.count: 10
--|     mapred.job.tracker.http.address: 0.0.0.0:50030
--|     mapred.job.tracker.http.address: 0.0.0.0:50030
--|     mapred.job.tracker.jobhistory.lru.cache.size: 5
--|     mapred.job.tracker.persist.jobstatus.active: false
--|     mapred.job.tracker.persist.jobstatus.dir: /jobtracker/jobsInfo
--|     mapred.job.tracker.persist.jobstatus.hours: 0
--|     mapred.job.tracker.retiredjobs.cache.size: 1000
--|     mapred.task.tracker.http.address: 0.0.0.0:50060
--|_    mapred.task.tracker.report.address: 127.0.0.1:0

author = "John R. Bond (john.r.bond@gmail.com)"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({35871}, "flume-master")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

function add_target(hostname) 
	if target.ALLOW_NEW_TARGETS then
		stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, hostname))
		local status,err = target.add(hostname)
	end
end

-- ref: http://lua-users.org/wiki/TableUtils
function table_count(tt, item)
	local count
	count = 0
	for ii,xx in pairs(tt) do
		if item == xx then count = count + 1 end
	end
	return count
end

parse_page = function( host, port, uri, intresting_keys )
	local result = {}
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response" ))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		for name,value in string.gmatch(body,"<tr><th>([^][<]+)</th>%s*<td><div%sclass=[^][>]+>([^][<]+)") do
			stdnse.print_debug(1, ("%s:  %s=%s "):format(SCRIPT_NAME,name,value:gsub("^%s*(.-)%s*$", "%1")))
			if nmap.verbosity() > 1 then
				 result[#result+1] = ("%s: %s"):format(name,value:gsub("^%s*(.-)%s*$", "%1"))
			else
				for i,v in ipairs(intresting_keys) do
					if name:match(("^%s"):format(v)) then
						result[#result+1] = ("%s: %s"):format(name,value:gsub("^%s*(.-)%s*$", "%1"))
					end
				end
			end
		end
	end
	return result
end

action = function( host, port )

	local result = {}
	local uri = "/flumemaster.jsp"
	local env_uri = "/masterenv.jsp"
	local config_uri = "/masterstaticconfig.jsp"
	local env_keys = {"java.runtime","java.version","java.vm.name","java.vm.vendor","java.vm.version","os","user.name","user.country","user.language,user.timezone"}
	local config_keys = {"dfs.datanode.address","dfs.datanode.http.address","dfs.datanode.https.address","dfs.datanode.ipc.address","dfs.http.address","dfs.https.address","dfs.secondary.http.address","flume.collector.dfs.dir","flume.collector.event.host","flume.master.servers","fs.default.name","mapred.job.tracker","mapred.job.tracker.http.address","mapred.task.tracker.http.address","mapred.task.tracker.report.address"}
	local nodes = {  }
	local zookeepers = {  }
	local hbasemasters = {  }
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		local capacity = {}
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		if body:match("Version:%s*</b>([^][,]+)") then
			local version = body:match("Version:%s*</b>([^][,]+)")
			stdnse.print_debug(1, ("%s: Version %s"):format(SCRIPT_NAME,version))
			result[#result+1] =  ("Version: %s"):format(version)
			port.version.version = version
		end
		if body:match("Compiled:%s*</b>([^][<]+)") then
			local compiled = body:match("Compiled:%s*</b>([^][<]+)")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			result[#result+1] =  ("Compiled: %s"):format(compiled)
		end
		if body:match("ServerID:%s*([^][<]+)") then
			local upgrades = body:match("ServerID:%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: ServerID %s"):format(SCRIPT_NAME,upgrades))
			result[#result] = ("ServerID: %s"):format(upgrades)
		end
		for logical,physical,hostname in string.gmatch(body,"<tr><td>([%w%.-_:]+)</td><td>([%w%.]+)</td><td>([%w%.]+)</td>") do
			stdnse.print_debug(2, ("%s:  %s (%s) %s"):format(SCRIPT_NAME,physical,logical,hostname))
			if (table_count(nodes, hostname) == 0) then
				nodes[#nodes+1] = hostname
				add_target(hostname)
			end
		end
		if next(nodes) ~= nil then 
			table.insert(result, "Flume nodes:")
			result[#result+1] = nodes
		end
		for zookeeper in string.gmatch(body,"Dhbase.zookeeper.quorum=([^][\"]+)") do
			if (table_count(zookeepers, zookeeper) == 0) then
				zookeepers[#zookeepers+1] = zookeeper
				add_target(zookeeper)
			end
		end
		if next(zookeepers) ~= nil then 
			result[#result+1] = "Zookeeper Master:"
			result[#result+1] = zookeepers
		end
		for hbasemaster in string.gmatch(body,"Dhbase.rootdir=([^][\"]+)") do
			if (table_count(hbasemasters, hbasemaster) == 0) then
				hbasemasters[#hbasemasters+1] = hbasemaster
				add_target(hbasemaster)
			end
		end
		if next(hbasemasters) ~= nil then 
			result[#result+1] = "Hbase Master Master:"
			result[#result+1] = hbasemasters
		end
		local vars = parse_page(host, port, env_uri, env_keys )
		if next(vars) ~= nil then
			result[#result+1] = "Enviroment: "
			result[#result+1] = vars
		end
		local vars = parse_page(host, port, config_uri, config_keys )
		if next(vars) ~= nil then
			result[#result+1] = "Config: "
			result[#result+1] = vars
		end
		if #result > 0 then
			port.version.name = "flume-master"
			port.version.product = "Apache Flume"
			nmap.set_port_version(host, port)
		end
		return stdnse.format_output(true, result)
	end
end
