description = [[
Compares the detected service on a port against the expected service and
reports deviations. The script requires that a version scan has been run in
order to be able to discover what service is running on each port.
]]

---
-- @usage
-- nmap --script unusual-port <ip>
--
-- @output
-- 23/tcp open   ssh     OpenSSH 5.8p1 Debian 7ubuntu1 (protocol 2.0)
-- |_unusual-port: ssh unexpected on port tcp/23
-- 25/tcp open   smtp    Postfix smtpd
--

-- Version 0.1
-- Created 11/25/2011 - v0.1 - created by Patrik Karlsson
author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "safe" }

require 'datafiles'

portrule = function() return true end
hostrule = function() return true end

-- the hostrule is only needed to warn 
hostaction = function(host)
	local port, state = nil, "open"
	local is_version_scan = false

	-- iterate over ports and check whether name_confidence > 3 this would
	-- suggest that a version scan has been run
	for _, proto in ipairs({"tcp", "udp"}) do
		repeat
			port = nmap.get_ports(host, port, proto, state)
			if ( port and port.version.name_confidence > 3 ) then
				is_version_scan = true
				break
			end
		until( not(port) )
	end

	-- if no version scan has been run, warn the user as the script requires a
	-- version scan in order to work.
	if ( not(is_version_scan) ) then
		return stdnse.format_output(true, "WARNING: this script depends on Nmap's service/version detection (-sV)")
	end
	
end

portaction = function(host, port)
	nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
	nmap.registry[SCRIPT_NAME]['services'] = nmap.registry[SCRIPT_NAME]['services'] or {}

	for _, proto in ipairs({"tcp","udp"}) do
		if ( not(nmap.registry[SCRIPT_NAME]['services'][proto]) ) then
			local status, svc_table = datafiles.parse_services(proto)
			if ( status ) then
				nmap.registry[SCRIPT_NAME]['services'][proto] = svc_table
			end	
		end
	end
	
	if ( port.version.name_confidence > 3 and port.service and 
		 port.service ~= nmap.registry[SCRIPT_NAME]['services'][port.protocol][port.number] ) then
		return ("%s unexpected on port %s/%d"):format(port.service, port.protocol, port.number)
	end	
end

local Actions = {
  hostrule = hostaction,
  portrule = portaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
