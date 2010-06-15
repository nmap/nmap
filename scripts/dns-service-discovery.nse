description=[[ 
Attempts to discover a hosts services using the DNS Service Discovery protocol.

The script first sends a query for _services._dns-sd._udp.local to get a
list of services. It then sends a followup query for each one to try to
get more information.
]]


---
-- @usage
-- nmap --script=dns-service-discovery -p 5353 <host>
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


-- Version 0.3
-- Created 01/06/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/13/2010 - v0.2 - modified to use existing dns library instead of mdns, changed output to be less DNS like
-- Revised 02/01/2010 - v0.3 - removed incorrect try/catch statements

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require 'shortport'
require 'dns'

portrule = shortport.portnumber(5353, "udp")

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
	local port_a = a.name:match("^(%d+)") or 0
	local port_b = b.name:match("^(%d+)") or 0
		
	if ( tonumber(port_a) < tonumber(port_b) ) then
		return true
	end
	return false
end

action = function(host, port)

	local result = {}
	local deviceinfo = {}	
	local status, response = dns.query( "_services._dns-sd._udp.local", { port = 5353, host = host.ip, dtype="PTR", retAll=true} )
	
	if not status then
		return
	end
	
	-- for each service response in answers, send a service query
	for _, v in ipairs( response ) do

		local service = {}
		local txt = {}
		local ip, ipv6, srv, address, port, proto
		
		status, response = dns.query( v, { port = 5353, host = host.ip, dtype="PTR", retPkt=true} )

		if not status then
			return
		end

		status, ip = getRecordType( dns.types.A, response, false )
		
		if status then
			address = ip
		end
		
		status, ipv6 = getRecordType( dns.types.AAAA, response, false )
		
		if status then
			address = address .. " " .. ipv6
		end
		
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

		if v == "_device-info._tcp.local" then
			service.name = "Device Information"
			deviceinfo = service
		else
			local serviceparams = stdnse.strsplit("[.]", v)
			
			if #serviceparams > 2 then
				local servicename = serviceparams[1]:sub(2)
				local proto = serviceparams[2]:sub(2)
				
				if port == nil or proto == nil or servicename == nil then
					service.name = v
				else
					service.name = string.format( "%s/%s %s", port, proto, servicename)
				end
			end
			
			table.insert( result, service )
			
		end
		
	end
	
	-- sort the tables per port
	table.sort( result, serviceCompare )
	
	-- we want the device information at the end
	table.insert( result, deviceinfo )
	
	-- set port to open
	nmap.set_port_state(host, port, "open")
		
	return stdnse.format_output(true, result )
	
end
