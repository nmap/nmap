id = "NBSTAT"
description = [[
Attempt's to get the target's NetBIOS names and MAC address.
\n\n
By default, the script displays the name of the computer and the logged-in
user; if the verbosity is turned up, it displays all names the system thinks it
owns.
\n\n
For more information on the NetBIOS protocol, see 'nselib/netbios.lua'.
]]

---
-- @usage
-- sudo nmap -sU --script nbstat.nse -p137 <host>\n
--
-- @output
-- (no verbose)\n
-- |_ NBSTAT: NetBIOS name: TEST1, NetBIOS user: RON, NetBIOS MAC: 00:0c:29:f9:d9:28\n
--\n
-- (verbose)\n
-- |  NBSTAT: NetBIOS name: TEST1, NetBIOS user: RON, NetBIOS MAC: 00:0c:29:f9:d9:28\n
-- |  Name: TEST1<00>            Flags: <unique><active>\n
-- |  Name: TEST1<20>            Flags: <unique><active>\n
-- |  Name: WORKGROUP<00>        Flags: <group><active>\n
-- |  Name: TEST1<03>            Flags: <unique><active>\n
-- |  Name: WORKGROUP<1e>        Flags: <group><active>\n
-- |  Name: RON<03>              Flags: <unique><active>\n
-- |  Name: WORKGROUP<1d>        Flags: <unique><active>\n
-- |_ Name: \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>\n

author = "Brandon Enright <bmenrigh@ucsd.edu>, Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- Current version of this script was based entirly on Implementing CIFS, by 
-- Christopher R. Hertel. 
categories = {"default", "discovery", "safe"}

require "netbios"

-- I have excluded the port function param because it doesn't make much sense
-- for a hostrule.  It works without warning.  The NSE documentation is
-- not explicit enough in this regard.  
hostrule = function(host)

	-- The following is an attempt to only run this script against hosts
	-- that will probably respond to a UDP 137 probe.  One might argue
	-- that sending a single UDP packet and waiting for a response is no
	-- big deal and that it should be done for every host.  In that case
	-- simply change this rule to always return true.

	local port_t135 = nmap.get_port_state(host,
		{number=135, protocol="tcp"})
	local port_t139 = nmap.get_port_state(host,
		{number=139, protocol="tcp"})
	local port_t445 = nmap.get_port_state(host,
		{number=445, protocol="tcp"})
	local port_u137 = nmap.get_port_state(host,
		{number=137, protocol="udp"})

	if (
		(port_t135 ~= nil and port_t135.state == "open") or
		(port_t139 ~= nil and port_t139.state == "open") or
		(port_t445 ~= nil and port_t445.state == "open") or
		(port_u137 ~= nil and
			(port_u137.state == "open" or
			port_u137.state == "open|filtered")))
	then
		return true
	else
		return false
	end	
end


action = function(host)

	local i
	local status
	local names, statistics
	local server_name, user_name
	local mac
	local result = ""

	-- Get the list of NetBIOS names
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	if(status == false) then
		return "ERROR: " .. names
	end

	-- Get the server name
	status, server_name = netbios.get_server_name(host.ip, names)
	if(status == false) then
		return "ERROR: " .. server_name
	end

	-- Get the logged in user
	status, user_name = netbios.get_user_name(host.ip, names)
	if(status == false) then
		return "ERROR: " .. user_name
	end

	-- Format the Mac address in the standard way
	mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", statistics:byte(1), statistics:byte(2), statistics:byte(3), statistics:byte(4), statistics:byte(5), statistics:byte(6))
	-- Samba doesn't set the Mac address
	if(mac == "00:00:00:00:00:00") then
		mac = "<unknown>"
	end

	-- Check if we actually got a username
	if(user_name == nil) then
		user_name = "<unknown>"
	end

	result = result .. string.format("NetBIOS name: %s, NetBIOS user: %s, NetBIOS MAC: %s\n", server_name, user_name, mac)

	-- If verbosity is set, dump the whole list of names
	if(nmap.verbosity() >= 1) then
		for i = 1, #names, 1 do
			local padding = string.rep(" ", 17 - string.len(names[i]['name']))
			local flags_str = netbios.flags_to_string(names[i]['flags'])
			result = result .. string.format("Name: %s<%02x>%sFlags: %s\n", names[i]['name'], names[i]['suffix'], padding, flags_str)
		end

		-- If super verbosity is set, print out the full statistics
		if(nmap.verbosity() >= 2) then
			result = result .. "Statistics: "
			for i = 1, #statistics, 1 do
				result = result .. string.format("%02x ", statistics:byte(i))
			end
			result = result .. "\n"
		end
	end


	return result

end
