local coroutine = require "coroutine"
local dhcp6 = require "dhcp6"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Sends a DHCPv6 request (Solicit) to the DHCPv6 multicast address,
parses the response, then extracts and prints the address along with
any options returned by the server.

The script requires Nmap to be run in privileged mode as it binds the socket
to a privileged port (udp/546).
]]

---
-- @usage
-- nmap -6 --script broadcast-dhcp6-discover
--
-- @output
-- | broadcast-dhcp6-discover: 
-- |   Interface: en0
-- |     Message type: Advertise
-- |     Transaction id: 74401
-- |     Options
-- |       Client identifier: MAC: 68:AB:CD:EF:AB:CD; Time: 2012-01-24 20:36:48
-- |       Server identifier: MAC: 08:FE:DC:BA:98:76; Time: 2012-01-20 11:44:58
-- |       Non-temporary Address: 2001:db8:1:2:0:0:0:1000
-- |       DNS Servers: 2001:db8:0:0:0:0:0:35
-- |       Domain Search: example.com, sub.example.com
-- |_      NTP Servers: 2001:db8:1111:0:0:0:0:123, 2001:db8:1111:0:0:0:0:124
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function()
	if not nmap.is_privileged() then
		stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
		return false
	end

	if nmap.address_family() ~= 'inet6' then
		stdnse.print_debug("%s is IPv6 compatible only.", SCRIPT_NAME)
		return false
	end
	return true
end

-- Gets a list of available interfaces based on link and up filters
--
-- @param link string containing the link type to filter
-- @param up string containing the interface status to filter
-- @return result table containing the matching interfaces
local function getInterfaces(link, up)
	if( not(nmap.list_interfaces) ) then return end
	local interfaces, err = nmap.list_interfaces()
	local result
	if ( not(err) ) then
		for _, iface in ipairs(interfaces) do
			if ( iface.link == link and iface.up == up ) then
				result = result or {}
				result[iface.device] = true
			end
		end
	end
	return result
end

local function solicit(iface, result)
	local condvar = nmap.condvar(result)
	local helper = dhcp6.Helper:new(iface)
	if ( not(helper) ) then
		condvar "signal"
		return
	end
	
	local status, response = helper:solicit()
	if ( status ) then
		response.name=("Interface: %s"):format(iface)
		table.insert(result, response )
	end
	condvar "signal"
end

action = function(host, port)

	local iface = nmap.get_interface()
	local ifs, result, threads = {}, {}, {}
	local condvar = nmap.condvar(result)

	if ( iface ) then
		ifs[iface] = true
	else
		ifs = getInterfaces("ethernet", "up")
	end

	for iface in pairs(ifs) do
		local co = stdnse.new_thread( solicit, iface, result )
		threads[co] = true
	end
	
	-- wait until the probes are all done
	repeat
		for thread in pairs(threads) do
			if coroutine.status(thread) == "dead" then
				threads[thread] = nil
			end
		end
		if ( next(threads) ) then
			condvar "wait"
		end
	until next(threads) == nil

	return stdnse.format_output(true, result)
end
