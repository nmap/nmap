local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local string = require "string"

description = [[
Attempts to extract system information from an SNMP version 1 service.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-sysdescr <target>
--
-- @output
-- |  snmp-sysdescr: HP ETHERNET MULTI-ENVIRONMENT,ROM A.25.80,JETDIRECT,JD117,EEPROM V.28.22,CIDATE 08/09/2006
-- |_   System uptime: 28 days, 17:18:59 (248153900 timeticks)

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

---
-- Sends SNMP packets to host and reads responses
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
	try(socket:connect(host, port))
	
	local payload
	  
	-- build a SNMP v1 packet
	-- copied from packet capture of snmpget exchange
	-- get value: 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0)
	local options = {}
	options.reqId = 28428 -- unnecessary?
	payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, "1.3.6.1.2.1.1.1.0")))

	try(socket:send(payload))
	
	local status
	local response
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)

	if (not status) or (response == "TIMEOUT") then 
		return
	end
	
	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")
	
	local result
	result = snmp.fetchFirst(response)
	
	-- build a SNMP v1 packet
	-- copied from packet capture of snmpget exchange
	-- get value: 1.3.6.1.2.1.1.3.0 (SNMPv2-MIB::sysUpTime.0)
	local options = {}
	options.reqId = 28428
	payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, "1.3.6.1.2.1.1.3.0")))
	
	try(socket:send(payload))
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)

	if (not status) or (response == "TIMEOUT") then
		return result
	end
	
	try(socket:close())

	local uptime = snmp.fetchFirst(response)

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
		dayLabel = "day"
	else
		dayLabel = "days"
	end
	
	result = result .. "\n" .. string.format("  System uptime: %d %s, %d:%02d:%05.2f (%s timeticks)", days, dayLabel, hours, minutes, seconds, tostring(uptime))
	
	return result
end

