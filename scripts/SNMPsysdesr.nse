-- SNMP system detection script
-- rev 0.4 (6-11-2007)

id = "SNMPv1"

description = "Attempts to extract system information from SNMP service"

author = "Thomas Buchanan <tbuchanan@thecompassgrp.net>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"discovery", "safe"}

require "shortport"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

action = function(host, port)

	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	-- do some exception handling / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)
	
	-- connect to the potential SNMP system
	try(socket:connect(host.ip, port.number, "udp"))
	
	local payload
	  
	-- build a SNMP v1 packet
	-- copied from packet capture of snmpget exchange
	-- get value: 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0)
	payload = "\048\039\002\001\000\004\006" .. "public" -- community string = public
	payload = payload .. "\160\026\002\002\111\012\002\001"
	payload = payload .. "\000\002\001\000\048\014\048\012"
	payload = payload .. "\006\008\043\006\001\002\001\001"
	payload = payload .. "\001\000\005\000"
	
	try(socket:send(payload))
	
	local status
	local response
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)

	if (not status) then
		return
	end

	if (response == "TIMEOUT") then
		return
	end
	
	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")
	
	local result
	result = string.match(response, "\001\001%z\004.(.*)")
	
	-- build a SNMP v1 packet
	-- copied from packet capture of snmpget exchange
	-- get value: 1.3.6.1.2.1.1.3.0 (SNMPv2-MIB::sysUpTime.0)
	payload = "\048\039\002\001\000\004\006" .. "public" -- community string = public
	payload = payload .. "\160\026\002\002\101\040\002\001"
	payload = payload .. "\000\002\001\000\048\014\048\012"
	payload = payload .. "\006\008\043\006\001\002\001\001"
	payload = payload .. "\003\000\005\000"

	try(socket:send(payload))
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)

	if (not status) then
		return result
	end

	if (response == "TIMEOUT") then
		return result
	end
	
	try(socket:close())

	local start, stop = response:find("\006\001\002\001\001\003\000")

	if start == nil then
		return result
	end
	
	local uplen,uptime,s1,s2,s3,s4

	uplen = response:byte(stop + 2)

	s1,s2,s3,s4 = response:byte(stop + 3, stop + 3 + uplen)

	if uplen == 4 then
		uptime = s1*(2^24) + s2*(2^16) + s3*(2^8) + s4
	elseif uplen == 3 then
		uptime = s1*(2^16) + s2*(2^8) + s3
	elseif uplen == 2 then
		uptime = s1*(2^8) + s2
	elseif uplen == 1 then
		uptime = s1
	else
		return result
	end

	local days, hours, minutes, seconds, htime, mtime, stime
	days = math.floor(uptime / 8640000)
	htime = math.fmod(uptime, 8640000)
	hours = math.floor(htime / 360000)
	mtime = math.fmod(htime, 360000)
	minutes = math.floor(mtime / 6000)
	stime = math.fmod(mtime, 6000)
	seconds = stime / 100
	
	local dayLabel
	
	if days == 1 then
		dayLabel = " day, "
	else
		dayLabel = " days, "
	end
	
	result = result .. "\n  System uptime: " .. days .. dayLabel .. hours .. ":" .. minutes .. ":" .. seconds
	result = result .. " (" .. tostring(uptime) .. " timeticks)"
	
	return result
end

