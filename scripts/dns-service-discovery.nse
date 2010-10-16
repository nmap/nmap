description=[[ 
Attempts to discover a hosts services using the DNS Service Discovery protocol.

The script first sends a query for _services._dns-sd._udp.local to get a
list of services. It then sends a followup query for each one to try to
get more information.
]]


---
-- @usage
-- nmap --script=dns-service-discovery -p 5353 <target>
--
-- @output
-- PORT     STATE SERVICE  REASON
-- 5353/udp open  zeroconf udp-response
-- | dns-service-discovery:  
-- |   548/tcp afpovertcp
-- |     model=MacBook5,1
-- |     Address=192.168.0.2 fe80:0:0:0:223:6cff:1234:5678
-- |   3689/tcp daap
-- |     txtvers=1
-- |     iTSh Version=196609
-- |     MID=0xFB5338C04123456
-- |     Database ID=6FA9761FE123456
-- |     dmv=131078
-- |     Version=196616
-- |     OSsi=0x1F6
-- |     Machine Name=Patrik Karlsson\xE2\x80\x99s Library
-- |     Media Kinds Shared=1
-- |     Machine ID=8945A7123456
-- |     Password=0
-- |_    Address=192.168.0.2 fe80:0:0:0:223:6cff:1234:5678


-- Version 0.6
-- Created 01/06/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/13/2010 - v0.2 - modified to use existing dns library instead of mdns, changed output to be less DNS like
-- Revised 02/01/2010 - v0.3 - removed incorrect try/catch statements
-- Revised 10/04/2010 - v0.4 - added prerule and add target support <patrik@cqure.net>
-- Revised 10/05/2010 - v0.5 - added ip sort function and
-- Revised 10/10/2010 - v0.6 - multicast queries are now used in parallel to collect service information <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require 'shortport'
require 'dns'
require 'target'

portrule = shortport.portnumber(5353, "udp")
prerule = function() return true end

--- Gets a record from both the Answer and Additional section
--
-- @param dtype DNS resource record type.
-- @param response Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return Answer according to the answer fetcher for <code>dtype</code> or an Error message.
function getRecordType( dtype, response, retAll )

	local result = {}
	local status1, answers = dns.findNiceAnswer( dtype, response, retAll )
	
	if status1 then
		if retAll then
			for _, v in ipairs(answers) do
				table.insert(result, string.format("%s", v) )
			end
		else
			return true, answers
		end
	end
	
	local status2, answers = dns.findNiceAdditional( dtype, response, retAll )

	if status2 then
		if retAll then
			for _, v in ipairs(answers) do
				table.insert(result, v)
			end
		else
			return true, answers
		end
	end
	
	if not status1 and not status2 then
		return false, answers
	end
	
	return true, result
	
end

--- Function used to compare discovered DNS services so they can be sorted
--
-- @param a table containing first item
-- @param b table containing second item
-- @return true if the port of a is less than the port of b
local function serviceCompare(a, b)
	-- if no port is found use 999999 for comparing, this way all services
	-- without ports and device information gets printed at the end
	local port_a = a.name:match("^(%d+)") or 999999
	local port_b = b.name:match("^(%d+)") or 999999
		
	if ( tonumber(port_a) < tonumber(port_b) ) then
		return true
	end
	return false
end

--- Converts a string ip to a numeric value suitable for comparing
--
-- @param ip string containing the ip to convert
-- @return number containing the converted ip
local function ipToNumber(ip)
	local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
	return (256^3) * o1 + (256^2) * o2 + (256^1) * o3 + (256^0) * o4
end

--- Compare function used for sorting IP-addresses
--
-- @param a table containing first item
-- @param b table containing second item
-- @return true if the port of a is less than the port of b
local function ipCompare(a, b)
	local ip_a = ipToNumber(a.name) or 0
	local ip_b = ipToNumber(b.name) or 0
	
	if ( tonumber(ip_a) < tonumber(ip_b) ) then
		return true
	end
	return false
end

--- Send a query for a particular service and store the response in a table
--
-- @param host string containing the ip to connect to
-- @param port number containing the port to connect to
-- @param svc the service record to retrieve
-- @param multiple true if responses from multiple hosts are expected
-- @param svcresponse table to which results are stored
local function queryService( host, port, svc, multiple, svcresponse )
	local condvar = nmap.condvar(svcresponse)
	local status, response = dns.query( svc, { port = port, host = host, dtype="PTR", retPkt=true, retAll=true, multiple=multiple, sendCount=1, timeout=2000} )
	if not status then 
		stdnse.print_debug("Failed to query service: %s; Error: %s", svc, response)
		return
	end
	svcresponse[svc] = svcresponse[svc] or {}
	if ( multiple ) then
		for _, r in ipairs(response) do
			table.insert( svcresponse[svc], r )
		end
	else
		svcresponse[svc] = response
	end
	condvar("broadcast")
end

--- Sends a unicast query for each discovered service to each host
--
-- @param host string containing the ip to connect to
-- @param record string containing the DNS record to query
-- @param result table to which the results are added
local function processRecords( response, result )
	local service, deviceinfo = {}, {}
	local txt = {}
	local ip, ipv6, srv, address, port, proto
	
	local record = ( #response.questions > 0 and response.questions[1].dname ) and response.questions[1].dname or ""

	status, ip = getRecordType( dns.types.A, response, false )
	if status then address = ip	end
	
	status, ipv6 = getRecordType( dns.types.AAAA, response, false )
	if status then address = address .. " " .. ipv6	end
	
	status, txt = getRecordType( dns.types.TXT, response, true )
	if status then
		for _, v in ipairs(txt) do
			if v:len() > 0 then
				table.insert(service, v)
			end
		end
	end
	
	status, srv = getRecordType( dns.types.SRV, response, false )
	if status then
		local srvparams = stdnse.strsplit( ":", srv )
		
		if #srvparams > 3 then
			port = srvparams[3]
		end
	end
			
	if address then
		table.insert( service, ("Address=%s"):format( address ) )
	end

	if record == "_device-info._tcp.local" then
		service.name = "Device Information"
		deviceinfo = service
		table.insert(result, deviceinfo)
	else
		local serviceparams = stdnse.strsplit("[.]", record)
		
		if #serviceparams > 2 then
			local servicename = serviceparams[1]:sub(2)
			local proto = serviceparams[2]:sub(2)
			
			if port == nil or proto == nil or servicename == nil then
				service.name = record
			else
				service.name = string.format( "%s/%s %s", port, proto, servicename)
			end
		end
		table.insert( result, service )
	end

end


--- Returns the amount of currenlty active threads
--
-- @param threads table containing the list of threads
-- @return count number containing the number of non-dead threads
threadCount = function( threads )
	local count = 0
	
	for thread in pairs(threads) do
		if ( coroutine.status(thread) == "dead" ) then
			threads[thread] = nil
		else
			count = count + 1
		end
	end
	return count
end

--- Creates a service host table 
--
-- ['_ftp._tcp.local'] = {10.10.10.10,20.20.20.20}
-- ['_http._tcp.local'] = {30.30.30.30,40.40.40.40}
--
-- @param response containing the response from <code>dns.query</code>
-- @return services table containing the service name as a key and all host addresses as value
local function createSvcHostTbl( response )
	local services = {}
	-- Create unique table of services
	for _, r in ipairs( response ) do
		for _, svc in ipairs(r.output ) do
			services[svc] = services[svc] or {}
			table.insert(services[svc], r.peer)
		end
	end
	
	return services
end

preaction = function()
	local result = {}
	local host, port = "224.0.0.251", 5353
	local status, response = dns.query( "_services._dns-sd._udp.local", { port = port, host = host, dtype="PTR", retAll=true, multiple=true, sendCount=1, timeout=2000} )
	if not status then return end

	local services = createSvcHostTbl(response)
	local ipsvctbl = {}
	local svcresponse = {}
	local condvar = nmap.condvar( svcresponse )
	local threads = {}

	-- Start one collector thread for each service
	for svc in pairs(services) do 
		local co = stdnse.new_thread( queryService, host, port, svc, true, svcresponse )
		threads[co] = true
	end

	-- Wait for all threads to finish running
	while threadCount(threads)>0 do
   		condvar("wait")
 	end

	-- Process all records that were returned
	for svcname, response in pairs(svcresponse) do
		for _, r in ipairs( response ) do
			ipsvctbl[r.peer] = ipsvctbl[r.peer] or {}
			processRecords( r.output, ipsvctbl[r.peer] )
		end
	end

	-- Restructure and build our output table
	for ip, svctbl in pairs( ipsvctbl ) do
		table.sort(svctbl, serviceCompare)
		svctbl.name = ip
		if target.ALLOW_NEW_TARGETS then target.add(ip)	end
		table.insert( result, svctbl )
	end
	table.sort( result, ipCompare )

	return stdnse.format_output(true, result )
end

scanaction = function(host, port)
	local result = {}
	local status, response = dns.query( "_services._dns-sd._udp.local", { port = 5353, host = host.ip, dtype="PTR", retAll=true, sendCount=1, timeout=2000 } )
	if not status then return end

	local svcresponse = {}
	local condvar = nmap.condvar( svcresponse )
	local threads = {}

	-- Start one collector thread for each service
	for _, svc in ipairs(response) do 
		local co = stdnse.new_thread( queryService, host.ip, port, svc, false, svcresponse )
		threads[co] = true
	end

	-- Wait for all threads to finish running
	while threadCount(threads)>0 do
   		condvar("wait")
 	end

	-- Process all records that were returned
	for svcname, response in pairs(svcresponse) do
		processRecords( response, result )
	end
	
	-- sort the tables per port
	table.sort( result, serviceCompare )

	-- set port to open
	nmap.set_port_state(host, port, "open")
		
	return stdnse.format_output(true, result )
		
end

-- Function dispatch table
local actions = {
	prerule = preaction,
	hostrule = scanaction,
	portrule = scanaction,
}

function action (...) return actions[SCRIPT_TYPE](...) end

