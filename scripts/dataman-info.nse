local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"

--Usage:
--Identify Cognex scanners
--nmap -sU -p 1069 -script cognex-info <host>


--Output Example:
--PORT		STATE	SERVICE 	REASON
--1069/udp	open	Cognex		syn-ack
--| cognex-info:
--|   modelName: DM262
--|   productName: Dataman DM262 Series Sensor
--|   deviceName: DM262-55D1EA
--|   firmware: 5.6.3_SR3
--|   serialNumber: 1A1803PP030235
--|   deviceIp: 192.168.1.123
--|   netmask: 255.255.255.0
--|   gateway: 192.168.1.1
--|_  macAddress: 00D02455D1EA

description = [[
This script sends a request packet to the Cognex scanner on port 1069 over UDP. Once the correct header
has been received, the script will attempt to parse out the productName, firmware, serialNumber, 
and macAddress.
]]

author = "Tri Quach"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

function set_nmap(host, port)
	port.state = "open"
	port.version.name = "CognexUDP"
	port.version.product = "Cognex Scanner"
	nmap.set_port_version(host, port)
	nmap.set_port_state(host, port, "open")	
end

portrule = shortport.port_or_service(1069, "Cognex", "udp")

action = function(host,port)
	local cognexQuery = stdnse.fromhex("43474e4d0400020000")
	-- create table for output
	local output = stdnse.output_table()
	-- create local vars for socket handling
	local socket, try, catch
	-- create new socket
	socket = nmap.new_socket()
	-- set timeout to 5s
	socket:set_timeout(5000)
	-- define the catch of the try statement
	catch = function()
		socket:close()
	end
	-- create new try
	try = nmap.new_try(catch)

	-- connect to port on host
	try(socket:connect(host, port))
	-- send Req Identity packet
	try(socket:send(cognexQuery))
	
	-- receive response via read everything
	local rcvstatus, Raw = socket:receive()
	if(rcvstatus == false) then
		return false, Raw
	end
	
	stdnse.print_debug(1, "Raw: %s", Raw)
	if (string.sub(Raw, 1, 4) == "CGNM") then
		-- get macAddress
		local macAddress = ""
		local Index = 12
		local Length = 0
		Index, Length = bin.unpack(">C", Raw, Index)
		for idx = Index, Index + Length - 1 do
			local idx, Octet = bin.unpack(">C", Raw, idx)
			if (Octet < 15) then
				macAddress = macAddress .. string.format("0%X", Octet)
			else
				macAddress = macAddress .. string.format("%X", Octet)
			end
			Index = idx
		end		
		-- increment by 5 to get to get modelName
		Index = Index + 5
		Index, Length = bin.unpack(">C", Raw, Index)
		local modelName = string.sub(Raw, Index, Index + Length - 1)
		Index = Index + Length
		-- increment by 2 to get to length of productName
		Index = Index + 1
		local Index, Length = bin.unpack(">C", Raw, Index)
		local productName = string.sub(Raw, Index, Index + Length - 1)
		Index = Index + Length
		-- increment to get to length of firmware
		Index = Index + 1
		local Index, Length = bin.unpack(">C", Raw, Index)
		local firmware = string.sub(Raw, Index, Index + Length - 1)
		Index = Index + Length
		-- increment to get to length of serialNumber
		Index = Index + 1
		local Index, Length = bin.unpack(">C", Raw, Index)
		local serialNumber = string.sub(Raw, Index, Index + Length - 1)
		Index = Index + Length
		-- increment to see how many to skip
		Index = Index + 3
		local Index, Length = bin.unpack(">C", Raw, Index)
		Index = Index + Length
		-- increment to get length of deviceName
		Index = Index + 1
		local Index, Length = bin.unpack(">C", Raw, Index)
		local deviceName = string.sub(Raw, Index, Index + Length - 1)
		Index = Index + Length
		-- increment to get ipAddress
		Index = Index + 2
		local dword
		Index, dword = bin.unpack("<I", Raw, Index)
		local ipAddress = ipOps.fromdword(dword)	
		-- increment to get netmask
		Index = Index + 3
		Index, dword = bin.unpack("<I", Raw, Index)
		local netmask = ipOps.fromdword(dword)
		Index, dword = bin.unpack("<I", Raw, Index)
		local gateway = ipOps.fromdword(dword)
		
		-- populate output table
		output["modelName"] = modelName
		output["productName"] = productName
		output["deviceName"] = deviceName
		output["serialNumber"] = serialNumber
		output["firmware"] = firmware
		output["deviceIp"] = ipAddress
		output["netmask"] = netmask
		output["gateway"] = gateway
		output["macAddress"] = macAddress
		
		set_nmap(host, port)
		socket:close()
		return output
	else
		socket:close()
		return nil
	end
end
