local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"

--Usage:
--Identify Cognex scanners
--nmap -sU -p 1069 --script cognex-info <host>


--Output Example:
--PORT		STATE	SERVICE 	REASON
--1069/udp	open	Cognex		script-set
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
	port.version.name = "Cognex"
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
	--socket:set_timeout(5000)
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
	
	stdnse.print_debug(1, "Raw hex: %s", stdnse.tohex(Raw))
	if (string.sub(Raw, 1, 4) == "CGNM") then
		-- get macAddress
		local macAddress = ""
		local Index = 12
		local Length = 0
		Length = string.unpack(">B", Raw, Index)
		for idx = Index + 1, Index + Length do
			local Octet = string.unpack(">B", Raw, idx)
			if (Octet < 15) then
				macAddress = macAddress .. string.format("0%X", Octet)
			else
				macAddress = macAddress .. string.format("%X", Octet)
			end
			Index = idx
		end
		stdnse.print_debug(1, "macAddress: %s", macAddress)
		-- increment by 6 to get to get modelName
		Index = Index + 6
		Length = string.unpack(">B", Raw, Index)
		local modelName = string.sub(Raw, Index + 1, Index + Length)
		stdnse.print_debug(1, "modelName: %s", modelName)
		Index = Index + Length
		-- increment by 2 to get to length of productName
		Index = Index + 2
		Length = string.unpack(">B", Raw, Index)
		local productName = string.sub(Raw, Index + 1, Index + Length)
		stdnse.print_debug(1, "productName: %s", productName)
		Index = Index + Length
		-- increment by 2 to get to length of firmware
		Index = Index + 2
		Length = string.unpack(">B", Raw, Index)
		local firmware = string.sub(Raw, Index + 1, Index + Length)
		stdnse.print_debug(1, "firmware: %s", firmware)
		Index = Index + Length
		-- increment by 2 to get to length of serialNumber
		Index = Index + 2
		Length = string.unpack(">B", Raw, Index)
		local serialNumber = string.sub(Raw, Index + 1, Index + Length)
		stdnse.print_debug(1, "serialNumber: %s", serialNumber)
		Index = Index + Length
		-- increment by 4 to see how many to skip
		Index = Index + 4
		Length = string.unpack(">B", Raw, Index)
		Index = Index + Length
		-- increment by 2 to get length of deviceName
		Index = Index + 2
		Length = string.unpack(">B", Raw, Index)
		local deviceName = string.sub(Raw, Index + 1, Index + Length)
		stdnse.print_debug(1, "deviceName: %s", deviceName)
		Index = Index + Length
		-- increment to get ipAddress
		Index = Index + 3
		local dword
		dword = string.unpack("<I4", Raw, Index)
		local ipAddress = ipOps.fromdword(dword)
		stdnse.print_debug(1, "ipAddress: %s", ipAddress)
		-- increment by 3 to get netmask
		Index = Index + 7
		dword = string.unpack("<I4", Raw, Index)
		local netmask = ipOps.fromdword(dword)
		stdnse.print_debug(1, "netmask: %s", netmask)
		-- increment by 3 to get gateway
		Index = Index + 4
		dword = string.unpack("<I4", Raw, Index)
		local gateway = ipOps.fromdword(dword)
		stdnse.print_debug(1, "gateway: %s", gateway)
		
		-- populate output table
		output["modelName"] = modelName
		output["productName"] = productName
		output["deviceName"] = deviceName
		output["serialNumber"] = serialNumber
		output["firmware"] = firmware
		output["ipAddress"] = ipAddress
		output["netmask"] = netmask
		output["gateway"] = gateway
		output["macAddress"] = macAddress
		
		-- set Nmap output
		set_nmap(host, port)
		-- close socket
		socket:close()
		-- return output table to Nmap
		return output
	else
		-- close socket
		socket:close()
		return nil
	end
end
