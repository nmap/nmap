local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local mongodb = stdnse.silent_require "mongodb"

description = [[
Attempts to get build info and server status from a MongoDB database.
]]

---
-- @usage
-- nmap -p 27017 --script mongodb-info <host>
-- @output
-- PORT      STATE SERVICE REASON
-- 27017/tcp open  unknown syn-ack
-- | mongodb-info:  
-- |   MongoDB Build info
-- |     ok = 1
-- |     bits = 64
-- |     version = 1.3.1-
-- |     gitVersion = d1f0ffe23bcd667f4ed18a27b5fd31a0beab5535
-- |     sysInfo = Linux domU-12-31-39-06-79-A1 2.6.21.7-2.ec2.v1.2.fc8xen #1 SMP Fri Nov 20 17:48:28 EST 2009 x86_64 BOOST_LIB_VERSION=1_41
-- |   Server status
-- |     opcounters
-- |       delete = 0
-- |       insert = 3
-- |       getmore = 0
-- |       update = 0
-- |       query = 10
-- |     connections
-- |       available = 19999
-- |       current = 1
-- |     uptime = 747
-- |     mem
-- |       resident = 9
-- |       virtual = 210
-- |       supported = true
-- |       mapped = 80
-- |     ok = 1
-- |     globalLock
-- |       ratio = 0.010762343463949
-- |       lockTime = 8037112
-- |       totalTime = 746780850
-- |     extra_info
-- |       heap_usage_bytes = 117120
-- |       note = fields vary by platform
-- |_      page_faults = 0

-- version 0.3
-- Created 01/12/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Revised 01/03/2012 - v0.3 - added authentication support <patrik@cqure.net>


author = "Martin Holst Swende"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

dependencies = {"mongodb-brute"}


local arg_db = stdnse.get_script_args(SCRIPT_NAME .. ".db") or "admin"

portrule = shortport.port_or_service({27017}, {"mongodb"})

function action(host,port)

	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(10000)
	-- do some exception  / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	try( socket:connect(host, port) )
	
	local req, statusresponse, buildinfo, err
	
	-- uglyness to allow creds.mongodb to work, as the port is not recognized
	-- as mongodb, unless a service scan was run
	local ps = port.service
	port.service = 'mongodb'
	local c = creds.Credentials:new(creds.ALL_DATA, host, port)
	for cred in c:getCredentials(creds.State.VALID + creds.State.PARAM) do
		local status, err = mongodb.login(socket, arg_db, cred.user, cred.pass)
		if ( not(status) ) then
			return err
		end
	end
	port.service = ps
	
	local status, packet = mongodb.serverStatusQuery()
	if not status then return packet end

	local statQResult, buildQResult
	status,statQResult = mongodb.query(socket, packet)
	
	if not status then return statQResult end
	
	port.version.name ='mongodb'
	port.version.product='MongoDB'
	port.version.name_confidence = 100
	nmap.set_port_version(host,port)

	status, packet = mongodb.buildInfoQuery()
	if not status then return packet end
	
	status, buildQResult =  mongodb.query(socket,packet )
	
	if not status then 
		stdnse.log_error(buildQResult) 
		return buildQResult
	end

	local versionNumber = buildQResult['version']
	port.version.product='MongoDB '..versionNumber
	nmap.set_port_version(host,port)

	local stat_out = mongodb.queryResultToTable(statQResult)
	local build_out = mongodb.queryResultToTable(buildQResult)
	local output = {"MongoDB Build info",build_out,"Server status",stat_out}
	
	return stdnse.format_output(true, output )
end
