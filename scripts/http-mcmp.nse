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
-- | http-mcmp: VULNERABLE
-- | Mod_cluster Management Protocol PING Result: 
-- | Type=PING-RSP&State=OK&id=000000001
-- | 
-- | Mod_cluster Management Protocol DUMP Result:
-- | balancer: [1] Name: mycluster Sticky: 1 [JSESSIONID]/[jsessionid] remove: 0 force: 0 Timeout: 0 maxAttempts: 1
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
	local try = nmap.new_try()
	local output_lines = {}
	local response = http.generic_request(host, port, 'PING', '/')
	if (response.status == 200) then
		if (http.response_contains(response, "Type=PING%-RSP")) then
			output_lines[ #output_lines+1 ] = 'VULNERABLE'
			output_lines[ #output_lines+1 ] = 'Mod_cluster Management Protocol PING Result: '
			output_lines[ #output_lines+1 ] = response.body
			response = http.generic_request(host, port, 'DUMP', '/')
			if (response.status == 200) then
				output_lines[ #output_lines+1 ] = 'Mod_cluster Management Protocol DUMP Result:'
				output_lines[ #output_lines+1 ] = response.body
			end
		end
	end
	return stdnse.strjoin("\n", output_lines)
end
