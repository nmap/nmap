description = [[
Checks if the webserver allows mod_cluster management protocol (MCMP) methods. 
This is a potential open proxy, or mitm vulnerability.
]]

-- Checks for Mod_cluster Management Protocol enabled webservices
--
--
-- @usage
-- nmap --script http-mcmp -p <port> <host>
--
-- @output
-- |   status: VULNERABLE
-- |   pingdesc: Mod_cluster Management Protocol PING Result:
-- |   pingresult: Type=PING-RSP&State=OK&id=000000001
-- |   dumpdesc: Mod_cluster Management Protocol DUMP Result:
-- |   dumpresult: balancer: [1] Name: mycluster Sticky: 1 [JSESSIONID]/[jsessionid] remove: 0 force: 0 Timeout: 0 maxAttempts: 1
-- | node: [1:1],Balancer: mycluster,JVMRoute: example,LBGroup: [],Host: 10.1.1.1,Port: 8080,Type: http,flushpackets: 0,flushwait: 10,ping: 10,smax: 120,ttl: 60,timeout: 0
-- | host: 1 [example.com] vhost: 1 node: 1
-- |_context: 1 [/test] vhost: 1 node: 1 status: 1
--
--
-- @author Frank Spierings 13/02/2016
--

author = "Frank Spierings"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "vuln", "discovery"}

local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
	local output = stdnse.output_table()
	local response = http.generic_request(host, port, 'PING', '/')
	if (response.status == 200) then
		if (http.response_contains(response, "Type=PING%-RSP")) then
			output.status = 'VULNERABLE'
			output.pingdesc = 'Mod_cluster Management Protocol PING Result: '
			output.pingresult = response.body
			response = http.generic_request(host, port, 'DUMP', '/')
			if (response.status == 200) then
				output.dumpdesc = 'Mod_cluster Management Protocol DUMP Result:'
				output.dumpresult = response.body
			end
		end
	else
		output.status = 'NOT vulnerable'
	end
	return output
end
