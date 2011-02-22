description = [[
Download IOS configuration using SNMP RW (v1) and displays the result or saves it to a file.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-ios-config --script-args snmpcommunity=<community> <target>
--
-- @output
-- | snmp-ios-config: 
-- | !
-- | version 12.3
-- | service timestamps debug datetime msec
-- | service timestamps log datetime msec
-- | no service password-encryption
-- | !
-- | hostname Router
-- | !
-- | boot-start-marker
-- | boot-end-marker
-- <snip>
--
-- @args snmp-ios-config.tftproot If set, specifies to what directory the downloaded config should be saved
--
-- Version 0.2
-- Created 01/03/2011 - v0.1 - created by Vikas Singhal
-- Revised 02/22/2011 - v0.2 - cleaned up and added support for built-in tftp, Patrik Karlsson <patrik@cqure.net>

author = "Vikas Singhal, Patrik Karlsson"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive"}

dependencies = {"snmp-brute"}

require "shortport"
require "snmp"
require "tftp"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

local function sendrequest(socket, oid, setparam)
	local payload
	local options = {}
	options.reqId = 28428 -- unnecessary?
	payload = snmp.encode(snmp.buildPacket(snmp.buildSetRequest(options, oid,setparam)))

	try(socket:send(payload))

	-- read in any response we might get
	local status, response = socket:receive()
	if ( not(status) ) then return status, response end
	
	local result = snmp.fetchFirst(response)
	return true
end

---
-- Sends SNMP packets to host and reads responses
action = function(host, port)
	
	local tftproot = stdnse.get_script_args("snmp-ios-config.tftproot")

	if ( tftproot and not( tftproot:match("[\\/]+$") ) ) then
		return "ERROR: tftproot needs to end with slash"
	end

   	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	-- do some exception handling / cleanup
	catch = function() socket:close() end
	
	try = nmap.new_try(catch)
	
	-- connect to the potential SNMP system
	try(socket:connect(host.ip, port.number, "udp"))

	local status, tftpserver, _, _, _ = socket:get_info()
	if( not(status) ) then
		return "ERROR: Failed to determin local ip"
	end
	
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.2.9999 (ConfigCopyProtocol is set to TFTP [1] )

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.2.9999",1)

	-- Fail silently if the first request doesn't get a proper response
	if ( not(request) ) then return	end

	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")

	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.3 (SourceFileType is set to running-config [4] )

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.3.9999",4)
	
	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.4 (DestinationFileType is set to networkfile [1] )

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.4.9999",1)
	
	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.15 (ServerAddress is set to the IP address of the TFTP server )
	
	local tbl = {}
	tbl._snmp = '40'
	for octet in tftpserver:gmatch("%d+") do
		table.insert(tbl, octet)
	end

	request = sendrequest(socket, nil, { { snmp.str2oid(".1.3.6.1.4.1.9.9.96.1.1.1.1.5.9999"), tbl } } )
	-- request = sendrequest(".1.3.6.1.4.1.9.9.96.1.1.1.1.5.9999",tftpserver)


	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.15 (ServerAddressType is set 1 for ipv4 ) 
	-- more options - 1:ipv4, 2:ipv6, 3:ipv4z, 4:ipv6z, 16:dns

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.15.9999",1)

	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.16 (ServerAddress is set to the IP address of the TFTP server )

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.16.9999",tftpserver)

	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.6 (CopyFilename is set to IP-config)

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.6.9999",host.ip .. "-config")

	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.14 (Start copying by setting CopyStatus to active [1])
	-- more options: 1:active, 2:notInService, 3:notReady, 4:createAndGo, 5:createAndWait, 6:destroy

	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.14.9999",1)
	
	-- wait for sometime and print the status of filetransfer	
	tftp.start()
	local status, infile = tftp.waitFile(host.ip .. "-config", 10)
	
	-- build a SNMP v1 packet
	-- get value: .1.3.6.1.4.1.9.9.96.1.1.1.1.10 (Check the status of filetransfer) 1:waiting, 2:running, 3:successful, 4:failed

	local options = {}
	options.reqId = 28428
	local payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, ".1.3.6.1.4.1.9.9.96.1.1.1.1.10.9999"))) 
	
	try(socket:send(payload))

	local status
	local response
	-- read in any response we might get
	status, response = socket:receive()

	if (not status) or (response == "TIMEOUT") then
		return "\n  ERROR: Failed to receive cisco configuration file"
	end
	
	local result
	result = snmp.fetchFirst(response)

	if result == 3 then
			result = ( infile and infile:getContent() )
			
			if ( tftproot ) then
				local fname = tftproot .. host.ip .. "-config"
				local file, err = io.open(fname, "w")
				if ( file ) then
					file:write(result)
					file:close()
				else
					return "\n  ERROR: " .. file
				end
				result = ("\n  Configuration saved to (%s)"):format(fname)
			end
	else
		result = "Not successful! error code: " .. result .. " (1:waiting, 2:running, 3:successful, 4:failed)"
 	end
	
	-------------------------------------------------
	-- build a SNMP v1 packet
	-- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.14 (Destroy settings by setting CopyStatus to destroy [6])
	
	request = sendrequest(socket, ".1.3.6.1.4.1.9.9.96.1.1.1.1.14.9999",6)
	
	try(socket:close())

	return result
end

