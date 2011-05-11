description = [[
Attempts to retrieve the target's NetBIOS names and MAC address.

By default, the script displays the name of the computer and the logged-in
user; if the verbosity is turned up, it displays all names the system thinks it
owns.
]]

---
-- @usage
-- sudo nmap -sU --script nbstat.nse -p137 <host>
--
-- @output
-- Host script results:
-- |_ nbstat: NetBIOS name: WINDOWS2003, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:c6:da:f5 (VMware)
--
-- Host script results:
-- |  nbstat:
-- |  |  NetBIOS name: WINDOWS2003, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:c6:da:f5 (VMware)
-- |  |  Names
-- |  |  |  WINDOWS2003<00>      Flags: <unique><active>
-- |  |  |  WINDOWS2003<20>      Flags: <unique><active>
-- |  |  |  SKULLSECURITY<00>    Flags: <group><active>
-- |  |  |  SKULLSECURITY<1e>    Flags: <group><active>
-- |  |  |  SKULLSECURITY<1d>    Flags: <unique><active>
-- |_ |_ |_ \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>


author = "Brandon Enright, Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- Current version of this script was based entirly on Implementing CIFS, by 
-- Christopher R. Hertel. 
categories = {"default", "discovery", "safe"}

require "netbios"
require "datafiles"

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

	return (port_t135 ~= nil and port_t135.state == "open") or
		(port_t139 ~= nil and port_t139.state == "open") or
		(port_t445 ~= nil and port_t445.state == "open") or
		(port_u137 ~= nil and
			(port_u137.state == "open" or
			port_u137.state == "open|filtered"))
end


action = function(host)

	local i
	local status
	local names, statistics
	local server_name, user_name
	local mac, prefix, manuf
	local response = {}
	local catch = function() return end
	local try = nmap.new_try(catch)
	

	-- Get the list of NetBIOS names
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	status, names, statistics = netbios.do_nbstat(host.ip)
	if(status == false) then
		return stdnse.format_output(false, names)
	end

	-- Get the server name
	status, server_name = netbios.get_server_name(host.ip, names)
	if(status == false) then
		return stdnse.format_output(false, server_name)
	end

	-- Get the logged in user
	status, user_name = netbios.get_user_name(host.ip, names)
	if(status == false) then
		return stdnse.format_output(false, user_name)
	end

	-- Build the MAC prefix lookup table
	if not nmap.registry.nbstat then
		-- Create the table in the registry so we can share between script instances
		nmap.registry.nbstat = {}
		nmap.registry.nbstat.mac_prefixes = try(datafiles.parse_mac_prefixes())
	end
	
	-- Format the Mac address in the standard way
	if(#statistics >= 6) then
		-- MAC prefixes are matched on the first three bytes, all uppercase
		prefix = string.upper(string.format("%02x%02x%02x", statistics:byte(1), statistics:byte(2), statistics:byte(3)))
		manuf = nmap.registry.nbstat.mac_prefixes[prefix]
		if manuf == nil then
			manuf = "unknown"
		end
		mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x (%s)", statistics:byte(1), statistics:byte(2), statistics:byte(3), statistics:byte(4), statistics:byte(5), statistics:byte(6), manuf)
		-- Samba doesn't set the Mac address, and nmap-mac-prefixes shows that as Xerox
		if(mac == "00:00:00:00:00:00 (Xerox)") then
			mac = "<unknown>"
		end
	else
		mac = "<unknown>"
	end

	-- Check if we actually got a username
	if(user_name == nil) then
		user_name = "<unknown>"
	end


	-- If verbosity is set, dump the whole list of names
	if(nmap.verbosity() >= 1) then
		table.insert(response, string.format("NetBIOS name: %s, NetBIOS user: %s, NetBIOS MAC: %s", server_name, user_name, mac))

		local names_output = {}
		names_output['name'] = "Names"
		for i = 1, #names, 1 do
			local padding = string.rep(" ", 17 - #names[i]['name'])
			local flags_str = netbios.flags_to_string(names[i]['flags'])
			table.insert(names_output, string.format("%s<%02x>%sFlags: %s", names[i]['name'], names[i]['suffix'], padding, flags_str))
		end

		table.insert(response, names_output)

		-- If super verbosity is set, print out the full statistics
		if(nmap.verbosity() >= 2) then
			local statistics_output = {}
			local statistics_string = ''
			statistics_output['name'] = "Statistics"
			for i = 1, #statistics, 1 do
				statistics_string = statistics_string .. string.format("%02x ", statistics:byte(i))
				if(i ~= #statistics and ((i) % 16) == 0) then
					table.insert(statistics_output, statistics_string)
					statistics_string = ''
				end
			end
			table.insert(statistics_output, statistics_string)
			table.insert(response, statistics_output)
		end

		return stdnse.format_output(true, response)
	else
		return string.format("NetBIOS name: %s, NetBIOS user: %s, NetBIOS MAC: %s", server_name, user_name, mac)
	end

end
