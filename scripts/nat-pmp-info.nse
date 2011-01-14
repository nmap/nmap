description = [[
Queries a NAT-PMP service for its external address.
]]

---
-- @usage
-- nmap -sU --script nat-pmp-info -p 5351 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 5351/udp open  unknown udp-response
-- | nat-pmp-info:   
-- |_  External ip: 1.2.3.4
--
--
-- The implementation is based on the following documentation:
-- http://files.dns-sd.org/draft-cheshire-nat-pmp.txt
--

--
-- Version 0.1
-- Created 09/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}

require "stdnse"
require "shortport"

portrule = shortport.port_or_service(5351, "nat-pmp", "udp")

process_response = function( data )

	--
	-- Make sure we received exactly 12 bytes:
	--
	--     0                   1                   2                   3
	--     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--    | Vers = 0      | OP = 128 + 0  | Result Code                   |
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--    | Seconds Since Start of Epoch                                  |
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--    | External IP Address (a.b.c.d)                                 |
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	
	if ( #data ~= 12 ) then return false, "Invalid length" end
	local pos, version, op, result, time = bin.unpack("CCSI", data )

	-- Make sure the result code is zero (OK)
	if ( result ~= 0 ) then 
		return false, ("Non-zero (%d) result code returned"):format(result)
	end
	
	local _, o1, o2, o3, o4 = bin.unpack("CCCC", data, pos )	
	return true, ("%d.%d.%d.%d"):format(o1,o2,o3,o4)

end

action = function( host, port )

	local socket = nmap.new_socket()
	local status = socket:connect( host, port, "udp" )

	socket:set_timeout(5000)
	
	--     0                   1
	--     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--    | Vers = 0      | OP = 0        |
	--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	--
	-- Layout of the query for external IP packet
	--
	local packet = string.char( 0, 0 )
	
	status = socket:send( packet )
	if( not(status) ) then 
		stdnse.print_debug(3, "ERROR: Failed to send data")
		return
	end
	
	local data
	status, data = socket:receive_bytes(12)
	if( not(status) ) then 
		stdnse.print_debug(3, "ERROR: Failed to receive data")
		return
	end
	
	local external_ip
	status, external_ip = process_response( data )
	if ( not(status) ) then	stdnse.print_debug(3, external_ip) end
	
	-- set port to open
	nmap.set_port_state(host, port, "open")
	port.version.name = "nat-pmp"
	nmap.set_port_version(host, port, "hardmatched")
	
	return ("  \n  External ip: %s"):format( external_ip )

end
