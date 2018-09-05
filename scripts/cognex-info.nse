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
--PORT		STATE	SERVICE			REASON
--1069/udp	open	cognex-insight	script-set
--| cognex-info:
--|   modelName: DM262
--|   productName: Dataman DM262 Series Sensor
--|   deviceName: DM262-55D1EA
--|   firmware: 5.6.3_SR3
--|   serialNumber: 1A1803PP030235
--|   deviceIp: 192.168.1.123
--|   netmask: 255.255.255.0
--|   gateway: 192.168.1.1
--|_  macAddress: 00:d0:24:55:d1:ea

description = [[
This script sends a request packet to the Cognex scanner on port 1069 over UDP. Once the correct header has been received, the script will attempt to parse out the modelName, productName, deviceName, firmware, serialNumber, deviceIp, netmask, gateway, and macAddress.
]]

author = "Tri Quach"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","version"}

function set_nmap(host, port)
	port.state = "open"
	port.version.name = "cognex-insight"
	port.version.product = "Cognex Scanner"
	nmap.set_port_version(host, port)
	nmap.set_port_state(host, port, "open")	
end

portrule = shortport.port_or_service(1069, "cognex-insight", "udp")

-- Here is wireshark's dump
--[[
0000   43 47 4e 4d 04 00 01 00 8e 01 21 06 00 d0 24 55   CGNM......!..Ð$U
0010   d1 ea 20 02 05 15 25 05 44 4d 32 36 32 28 1b 44   Ñê ...%.DM262(.D
0020   61 74 61 4d 61 6e 20 44 4d 32 36 32 20 53 65 72   ataMan DM262 Ser
0030   69 65 73 20 53 65 6e 73 6f 72 27 09 35 2e 37 2e   ies Sensor'.5.7.
0040   30 5f 73 72 32 26 0e 31 41 31 38 30 33 50 50 30   0_sr2&.1A1803PP0
0050   33 30 32 33 35 29 00 2b 16 04 68 74 74 70 9c ad   30235).+..http..
0060   06 74 65 6c 6e 65 74 17 00 03 6d 73 74 7d c7 22   .telnet...mst}Ç"
0070   11 44 4d 32 36 32 20 48 65 6c 6c 6f 20 57 6f 72   .DM262 Hello Wor
0080   6c 64 23 04 7b 01 a8 c0 24 0e 00 00 ff ff ff 01   ld#.{.¨À$...ÿÿÿ.
0090   01 a8 c0 00 00 00 00 00                           .¨À.....
--]]


action = function(host,port)
	-- send Cognex discovery header "CGNM", "0400020000" is the request header
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
	-- close socket
	socket:close()
	if(rcvstatus == false) then
		return nil
	end
	
	-- display raw bytes
	stdnse.print_debug(1, "Raw hex: %s", stdnse.tohex(Raw))
	
	-- abort if response header is not available
	if (stdnse.tohex(string.sub(Raw, 1, 9)) ~= "43474e4d040001008e") then
		return nil	
	end
	
	-- first 9 bytes are header response
	-- next 2 are something?
	-- get macAddress
	local Index = 12
	-- how many bytes to expect for MAC address (6)
	local macAddress, Index = string.unpack(">s1", Raw, Index)
	macAddress = stdnse.format_mac(macAddress)
	stdnse.print_debug(1, "macAddress: %s", macAddress)
	
	-- increment by 5 to get to get modelName
	Index = Index + 5
	local modelName, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "modelName: %s", modelName)
	
	-- increment by 1 to get to length of productName
	Index = Index +1
	local productName, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "productName: %s", productName)
	
	-- increment by 1 to get to length of firmware
	Index = Index + 1
	local firmware, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "firmware: %s", firmware)
	
	-- increment by 1 to get to length of serialNumber
	Index = Index + 1
	local serialNumber, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "serialNumber: %s", serialNumber)	
	
	-- increment by 3 to get the available options (http, telnet, mst)
	Index = Index + 3
	local options, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "options: %s", options)	
	
	-- increment by 1 to get length of deviceName
	Index = Index + 1
	local deviceName, Index = string.unpack(">s1", Raw, Index)
	stdnse.print_debug(1, "deviceName: %s", deviceName)
	
	-- increment by 2 to get ipAddress
	Index = Index + 2
	local dword, Index = string.unpack("<I4", Raw, Index)
	local ipAddress = ipOps.fromdword(dword)
	stdnse.print_debug(1, "ipAddress: %s", ipAddress)
	
	-- increment by 3 to get netmask
	Index = Index + 3
	local dword, Index = string.unpack("<I4", Raw, Index)
	local netmask = ipOps.fromdword(dword)
	stdnse.print_debug(1, "netmask: %s", netmask)
	
	-- get gateway
	local dword, Index = string.unpack("<I4", Raw, Index)
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
	-- return output table to Nmap
	return output
end
