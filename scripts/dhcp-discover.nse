description = [[
Sends a DHCPDISCOVER request to a host on UDP port 67. The response
comes back to UDP port 68, and
is read using pcap (due to the inability for a script to choose its source port at the moment). 

DHCPDISCOVER is a DHCP request that returns useful information from a DHCP server. The request sends 
a list of which fields it wants to know (a handful by default, every field if verbosity is turned on), and
the server responds with the fields that were requested. It should be noted that the server doesn't have
to return every field, nor does it have to return them in the same order, or honour the request at
all. A Linksys WRT54g, for example, completely ignores the list of requested fields and returns a few 
standard ones. This script displays every field it receives. 

With script arguments, the type of DHCP request can be changed, which can lead to interesting results. 
Additionally, the MAC address can be randomized, which should override the cache on the DHCP server and
assign a new IP address. Extra requests can also be sent to exhaust the IP address range more quickly. 

DHCPINFORM is another type of DHCP request that requests the same information, but doesn't reserve
an address. Unfortunately, because many home routers simply ignore DHCPINFORM requests, we opted
to use DHCPDISCOVER instead. 

Some of the more useful fields:
* DHCP Server (the address of the server that responded)
* Subnet Mask
* Router
* DNS Servers
* Hostname
]]

---
-- @args dhcptype The type of DHCP request to make. By default,  DHCPDISCOVER is sent, but this
--                argument can change it to DHCPOFFER,  DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, 
--                DHCPRELEASE or DHCPINFORM. Not all types will evoke a response from all servers,
--                and many require different fields to contain specific values. 
-- @args randomize_mac Set to <code>true</code> or <code>1</code> to  send a random MAC address with
--                the request (keep in mind that you may  not see the response). This should 
--                cause the router to reserve a new  IP address each time.
-- @args requests Set to an integer to make up to  that many requests (and display the results). 
-- @args fake_requests Set to an integer to make that many fake requests  before the real one(s).
--                This could be useful, for example, if you  also use <code>randomize_mac</code>
--                and you want to try exhausting  all addresses. 
--
-- @output
-- Interesting ports on 192.168.1.1:
-- PORT   STATE SERVICE
-- 67/udp open  dhcps
-- |  dhcp-discover:
-- |  |  IP Offered: 192.168.1.101
-- |  |  DHCP Message Type: DHCPOFFER
-- |  |  Server Identifier: 192.168.1.1
-- |  |  IP Address Lease Time: 1 day, 0:00:00
-- |  |  Subnet Mask: 255.255.255.0
-- |  |  Router: 192.168.1.1
-- |_ |_ Domain Name Server: 208.81.7.10, 208.81.7.14
-- 

author = "Ron Bowes"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "intrusive"}

require 'bin'
require 'bit'
require 'dhcp'
require 'ipOps'
require 'shortport'
require 'stdnse'

-- We want to run against a specific host if UDP/67 is open
function portrule(host, port)
	if nmap.address_family() ~= 'inet' then
		stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
		return false
	end

	return shortport.portnumber(67, "udp")(host, port)
end

-- We will want to run as a prerule any time
--prerule  = function()
--	return true
--end

local function go(host, port)
	-- We're going to need some low quality random numbers
	math.randomseed(os.time())

	-- Set up a fake host for prerule
	if(not(host)) then
		host = {}
		host.mac_addr_src = string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF)
		host.ip = "255.255.255.255"
		host.interface = "eth0" -- TODO: I'd like to have a better way of doing this
	end

	-- Create fake requests if the user asked to. These are fired and forgotten, we ignore the responses. 
	if(nmap.registry.args.fake_requests) then
		for i=1, tonumber(nmap.registry.args.fake_requests), 1 do
			-- Build and send a DHCP request using the specified request type, or DHCPDISCOVER
			local request_type = dhcp.request_types[nmap.registry.args.dhcptype or "DHCPDISCOVER"]
			if(request_type == nil) then
				return false, "Valid request types: " .. stdnse.strjoin(", ", dhcp.request_types_str)
			end

			-- Generate the MAC address, if it's random (TODO: if I can enumerate interfaces, I should fall back to that instead)
			local mac_addr = host.mac_addr_src
			if(nmap.registry.args.randomize_mac == 'true' or nmap.registry.args.randomize_mac == '1') then
				stdnse.print_debug(2, "dhcp-discover: Generating a random MAC address")
				mac_addr = ""
				for j=1, 6, 1 do
					mac_addr = mac_addr .. string.char(math.random(1, 255))
				end
			end

			local status, result = dhcp.make_request(host.ip, host.interface, request_type, "0.0.0.0", mac_addr)
			if(status == false) then
				stdnse.print_debug(1, "dhcp-discover: Couldn't send DHCP request: %s", result)
				return false, "Couldn't send DHCP request: " .. result
			end
		end
	end

	-- Build and send a DHCP request using the specified request type, or DHCPDISCOVER
	local requests = tonumber(nmap.registry.args.requests or 1)
	local results = {}
	for i = 1, requests, 1 do
		-- Decide which type of request to make
		local request_type = dhcp.request_types[nmap.registry.args.dhcptype or "DHCPDISCOVER"]
		if(request_type == nil) then
			return false, "Valid request types: " .. stdnse.strjoin(", ", dhcp.request_types_str)
		end
	
		-- Generate the MAC address, if it's random
		local mac_addr = host.mac_addr_src
		if(nmap.registry.args.randomize_mac == 'true' or nmap.registry.args.randomize_mac == '1') then
			stdnse.print_debug(2, "dhcp-discover: Generating a random MAC address")
			mac_addr = ""
			for j=1, 6, 1 do
				mac_addr = mac_addr .. string.char(math.random(1, 255))
			end
		end
	
		-- Receive the result
		local status, result = dhcp.make_request(host.ip, host.interface, request_type, "0.0.0.0", mac_addr)
		if(status == false) then
			stdnse.print_debug(1, "dhcp-discover: Couldn't send DHCP request: %s", result)
			return false, "Couldn't send DHCP request: " .. result
		end

		table.insert(results, result)
	end

	-- Done!
	return true, results
end

action = function(host, port)
	local status, results = go(host, port)


	if(status == false) then
		return stdnse.format_output(false, results)
	end

	if(results == nil) then
		return nil
	end

	-- Set the port state to open
	if(host) then
		nmap.set_port_state(host, port, "open")
	end

	local response = {}

	-- Display the results
	for i, result in ipairs(results) do
		local result_table = {}

		table.insert(result_table, string.format("IP Offered: %s", result.yiaddr_str))
		for _, v in ipairs(result.options) do
			if(type(v['value']) == 'table') then
				table.insert(result_table, string.format("%s: %s", v['name'], stdnse.strjoin(", ", v['value'])))
			else
				table.insert(result_table, string.format("%s: %s\n", v['name'], v['value']))
			end
		end

		if(#results == 1) then
			response = result_table
		else
			result_table['name'] = string.format("Result %d of %d", i, #results)
			table.insert(response, result_table)
		end
	end

	return stdnse.format_output(true, response)
end




