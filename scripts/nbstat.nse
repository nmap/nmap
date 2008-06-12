id = "NBSTAT"
description = "Sends a NetBIOS query to target host to try to determine \
the NetBIOS name and MAC address."
author = "Brandon Enright <bmenrigh@ucsd.edu>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- This script was created by reverse-engineering the packets
-- sent by NBTSCAN and hacking with the Wireshark NetBIOS
-- protocol dissector.  I do not believe this constitutes
-- a derivative work in the GPL sense of the phrase.

categories = {"default", "discovery", "safe"}

require "comm"

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


-- Again, I have excluded the port param.  Is this okay on a hostrule?
action = function(host)
	
	-- This is the UDP NetBIOS request packet.  I didn't feel like
	-- actually generating a new one each time so this has been shamelessly
	-- copied from a packet dump of nbtscan.
	-- See http://www.unixwiz.net/tools/nbtscan.html for code.
	-- The magic number in this code is \003\097.
	local data =
		"\003\097\000\016\000\001\000\000" ..
		"\000\000\000\000\032\067\075\065" ..
		"\065\065\065\065\065\065\065\065" ..
		"\065\065\065\065\065\065\065\065" ..
		"\065\065\065\065\065\065\065\065" ..
		"\065\065\065\065\065\000\000\033" ..
		"\000\001"

	local status, result = comm.exchange(host, 137, data, {bytes=1, proto="udp", timeout=5000})

	if (not status) then
		return
	end

	-- We got data back from 137, make sure we know it is open
	nmap.set_port_state(host, {number=137, protocol="udp"}, "open")

	-- Magic numbers:
	-- Offset to number of names returned: 57
	-- Useful name length: 15
	-- Name type length: 3
	-- Computer name type: \032\068\000 or \032\004\000
	-- User name type: \003\068\000 or \003\004\000
	-- Length of each name + name type: 19
	-- Length of MAC address: 6
	-- Note that string.sub includes a 0 char so these numbers are 1 less

	if (string.len(result) < 57) then
		return
	end

	-- Make sure the response at least looks like a NBTSTAT response
	-- The first 2 bytes are the magic number sent originally,  The second
	-- 2 bytes should be 0x84 0x00 (errorless name query response)
	if (string.sub(result, 1, 4) ~= "\003\097\132\000" ) then
		return
	end

	local namenum = string.byte(result, 57)

	if (string.len(result) < 58 + namenum * 18 + 6) then
		return
	end


	-- This loop will try to find the computer name.  This name needs to
	-- be found before the username because sometimes NetBIOS reports
	-- username flags with the computer name as text.
	local compname
	for i = 0, namenum - 1, 1 do
		-- Names come back trailing-space-padded so strip that off..
		local namefield = string.sub (result, 58 + i * 18,
			58 + i * 18 + 14)
		local iname
		local nameflags = string.sub (result, 58 + i * 18 + 15,
			58 + i * 18 + 15 + 2)
		local padindex = string.find(namefield, " ")
		if (padindex ~= nil and padindex > 1) then
			iname = string.sub(namefield, 1, padindex - 1)
		else
			iname = namefield
		end

		if (nameflags == "\032\068\000" or
			nameflags == "\032\004\000") then
			compname = iname
		end
	end

	if (compname == nil) then
		return
	end


	-- This loop will attempt to find the username logged onto the machine
	-- This is not possible on most Windows machines (I don't know why)
	-- Sometimes the flag that generally indicates the username
	-- returns the computer name instead.  This function will ignore
	-- the username if it matches the computer name.  This loop will not
	-- properly report the the username if it really happens to be
	-- the same as the computer name.
	local username
	for i = 0, namenum - 1, 1 do
		-- Names come back trailing-space-padded so strip that off..
		local namefield = string.sub (result, 58 + i * 18,
			58 + i * 18 + 14)
		local iname
		local nameflags = string.sub (result, 58 + i * 18 + 15,
			58 + i * 18 + 15 + 2)
		local padindex = string.find(namefield, " ")
		if (padindex ~= nil and padindex > 1) then
			iname = string.sub(namefield, 1, padindex - 1)
		else
			iname = namefield
		end

		if (nameflags == "\003\068\000" or
			nameflags == "\003\004\000") then
			if (string.find(iname, compname, 1, true) == nil) then
				username = iname
			end
		end
	end


	-- SAMBA likes to say its MAC is all 0s.  That could be detected...
	-- If people say printing a MAC of 0000.0000.000 is more wrong
        -- than not returning a MAC at all then fix it here.
	local macfield = string.sub (result, 58 + namenum * 18,
		58 + namenum * 18 + 5)
	local mac = string.format ("%02X:%02X:%02X:%02X:%02X:%02X",
		string.byte(macfield, 1),
		string.byte(macfield, 2),
		string.byte(macfield, 3),
		string.byte(macfield, 4),
		string.byte(macfield, 5),
		string.byte(macfield, 6))

	if (username ~= nil) then
		return "NetBIOS name: " .. compname ..
			", NetBIOS user: " .. username ..
			", NetBIOS MAC: " .. mac
	else
		return "NetBIOS name: " .. compname ..
			", NetBIOS MAC: " .. mac
	end
end
