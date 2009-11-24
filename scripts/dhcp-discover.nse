description = [[
Sends a DHCPDISCOVER request to a host on UDP port 67. The response come back to UDP port 68, and
is read using PCAP (due to the inability for a script to choose its source port at the moment). 

DHCPDISCOVER is a DHCP request that returns useful information from a DHCP server. The request sends 
a list of which fields it wants to know (a handful by default, every field if verbosity is turned on), and
the server responds with the fields that were requested. It should be noted that the server doesn't have
to return every field, nor does it have to return them in the same order, or honour the request at
all. A Linksys WRT54g, for example, completely ignores the list of requested fields and returns a few 
standard ones. This script displays every field it receives. 

Using various script-args, the type of DHCP request can be changed, which can lead to interesting results. 
Additionally, the MAC address can be randomized, which should override the cache on the DHCP server and
assign a new IP address. Extra requests can also be sent to exhaust the IP address range more quickly. 
See the 'args' section for more information. 

DHCPINFORM is another type of DHCP request that requests the same information, but doesn't reserve
an address. Unfortunately, because many home routers simply ignore DHCPINFORM requests, we opted
to use DHCPDISCOVER instead. 

Some of the more useful fields:
* DHCP Server (the address of the server that responded)
* Subnet Mask
* Router
* DNS Servers
* Hostname

The functions for creating and parsing DHCP requests are general, and should be able to create and
parse any DHCP request and response. If other scripts require DHCP support, <code>dhcp_build</code>
and <code>dhcp_parse</code>, with their related functions, can easily be abstracted into a NSELib. 
]]

---
--@output
-- Interesting ports on 192.168.1.1:
-- PORT   STATE SERVICE
-- 67/udp open  dhcps
-- |  dhcp-discover:
-- |  |  IP Offered: 192.168.1.101
-- |  |  DHCP Message Type: DHCPOFFER
-- |  |  Server Identifier: 192.168.1.1
-- |  |  IP Address Lease Time: 1 day, 0:00:00
-- |  |  Subnet Mask: 255.255.255.0
-- |  |  Router: 192.168.1.1
-- |_ |_ Domain Name Server: 208.81.7.10, 208.81.7.14
-- 
--
--@args dhcptype The type of DHCP request to make. By default, DHCPDISCOVER is sent, but this argument
--               can change it to DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE
--               or DHCPINFORM. Not all types will evoke a response from all servers. 
--@args randomize_mac Set to 'true' or '1' to send a random MAC address with the request (keep in mind
--               that you may not see the response). This should cause the router to reserve a new IP
--               adderss each time. 
--@args requests Set to an integer to make up to that many requests (and display the results). 
--@args fake_requests Set to an integer to make that many fake requests before the real one(s). This could
--               be useful, for example, if you also use <code>randomize_mac</code> and you want to try
--               exhausting all addresses. 
--@args timeout  Set to an integer to use it for a timeout. My router responds to <code>fake_requests</code>
--               rate limited, at about 1 response/second. Therefore, timeout has to be at least 
--               <code>fake_requests * 1000</code>. Default: 5000. 


author = "Ron Bowes"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "intrusive"}

require 'bin'
require 'bit'
require 'ipOps'
require 'shortport'
require 'stdnse'

local request_types = 
{
	DHCPDISCOVER = 1,
	DHCPOFFER    = 2,
	DHCPREQUEST  = 3,
	DHCPDECLINE  = 4,
	DHCPACK      = 5,
	DHCPNAK      = 6,
	DHCPRELEASE  = 7,
	DHCPINFORM   = 8
}


local request_types_str = {}
request_types_str[1] = "DHCPDISCOVER"
request_types_str[2] = "DHCPOFFER"
request_types_str[3] = "DHCPREQUEST"
request_types_str[4] = "DHCPDECLINE"
request_types_str[5] = "DHCPACK"
request_types_str[6] = "DHCPNAK"
request_types_str[7] = "DHCPRELEASE"
request_types_str[8] = "DHCPINFORM"


portrule = shortport.portnumber(67, "udp")

callback = function(packetsz, layer2, layer3)
	return string.sub(layer3, 33, 36)
end

---Read an IP address or a list of IP addresses. Print an error if the length isn't a multiple of 4. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_ip(data, pos, length)
	if(length ~= 4) then
		if((length % 4) ~= 0) then
			stdnse.print_debug("dhcp-discover: Invalid length for an ip address (%d)", length)
			pos = pos + length
	
			return pos, nil
		else
			local results = {}
			for i=1, length, 4 do
				local value
				pos, value = bin.unpack("<I", data, pos)
				table.insert(results, ipOps.fromdword(value))
			end

			return pos, results
		end
	else
		local value
		pos, value = bin.unpack("<I", data, pos)

		return pos, ipOps.fromdword(value)
	end
end

---Read a string. The length of the string is given by the length field. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_string(data, pos, length)
	return bin.unpack(string.format("A%d", length), data, pos)
end

---Read a single byte. Print an error if the length isn't 1. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_1_byte(data, pos, length)
	if(length ~= 1) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be %d)", length, 1)
		pos = pos + length
		return pos, nil
	end
	return bin.unpack("C", data, pos)
end

---Read a message type. This is a single-byte value that's looked up in the <code>request_types_str</code>
-- table. Print an error if the length isn't 1. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_message_type(data, pos, length)
	local value

	pos, value = read_1_byte(data, pos, length)
	if(value == nil) then
		return pos, nil
	end

	return pos, request_types_str[value]
end

---Read a single byte, and return 'false' if it's 0, or 'true' if it's non-zero. Print an error if the 
-- length isn't 1. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_boolean(data, pos, length)
	local result
	pos, result = read_1_byte(data, pos, length)

	if(result == nil) then
		return nil
	elseif(result == 0) then
		return "false"
	else
		return "true"
	end
end

---Read a 2-byte unsigned little endian value. Print an error if the length isn't 2. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_2_bytes(data, pos, length)
	if(length ~= 2) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be %d)", length, 2)
		pos = pos + length
		return pos, nil
	end
	return bin.unpack(">S", data, pos)
end


---Read a list of 2-byte unsigned little endian values. Print an error if the length isn't a multiple
-- of 2. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_2_bytes_list(data, pos, length)
	if((length % 2) ~= 0) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 2)
		pos = pos + length

		return pos, nil
	else
		local results = {}
		for i=1, length, 2 do
			local value
			pos, value = bin.unpack(">S", data, pos)
			table.insert(results, value)
		end

		return pos, results
	end
end


---Read a 4-byte unsigned little endian value. Print an error if the length isn't 4. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_4_bytes(data, pos, length)
	if(length ~= 4) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be %d)", length, 4)
		pos = pos + length
		return pos, nil
	end
	return bin.unpack(">I", data, pos)
end

---Read a 4-byte unsigned little endian value, and interpret it as a time offset value. Print an 
-- error if the length isn't 4. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_time(data, pos, length)
	local result
	if(length ~= 4) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be %d)", length, 4)
		pos = pos + length
		return pos, nil
	end
	pos, result = bin.unpack(">I", data, pos)

	-- This code was mostly taken from snmp-sysdescr.nse. It should probably be abstracted into stdnse.lua [TODO]
	local days, hours, minutes, seconds, htime, mtime, stime
	days = math.floor(result / 86400)
	htime = math.fmod(result, 86400)
	hours = math.floor(htime / 3600)
	mtime = math.fmod(htime, 3600)
	minutes = math.floor(mtime / 60)
	seconds = math.fmod(mtime, 60)

	local dayLabel

	if days == 1 then
		dayLabel = "day"
	else
		dayLabel = "days"
	end

	return pos, string.format("%d %s, %d:%02d:%02d", days, dayLabel, hours, minutes, seconds)
end

---Read a list of static routes. Each of them are a pair of IP addresses, a destination and a 
-- router. Print an error if the length isn't a multiple of 8. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_static_route(data, pos, length)
	if((length % 8) ~= 0) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 8)
		pos = pos + length

		return pos, nil
	else
		local results = {}
		for i=1, length, 8 do
			local destination, router
			pos, destination = read_ip(data, pos, 4)
			pos, router      = read_ip(data, pos, 4)
			table.insert(results, {destination=destination, router=router})
		end

		return pos, results
	end
end

---Read a list of policy filters. Each of them are a pair of IP addresses, an address and a 
-- mask. Print an error if the length isn't a multiple of 8. 
--
--@param data The packet.
--@param pos  The position in the packet. 
--@param length The length that the server claims the field is. 
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong. 
local function read_policy_filter(data, pos, length)
	if((length % 8) ~= 0) then
		stdnse.print_debug("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 8)
		pos = pos + length

		return pos, nil
	else
		local results = {}
		for i=1, length, 8 do
			local address, router
			pos, address = read_ip(data, pos, 4)
			pos, mask    = read_ip(data, pos, 4)
			table.insert(results, {address=address, mask=mask})
		end

		return pos, results
	end
end

---These are the different fields for DHCP
local actions = {}
actions[1]  = {name="Subnet Mask",                     func=read_ip,             default=true}
actions[2]  = {name="Time Offset",                     func=read_4_bytes,        default=false}
actions[3]  = {name="Router",                          func=read_ip,             default=true}
actions[4]  = {name="Time Server",                     func=read_ip,             default=true}
actions[5]  = {name="Name Server",                     func=read_ip,             default=true}
actions[6]  = {name="Domain Name Server",              func=read_ip,             default=true}
actions[7]  = {name="Log Server",                      func=read_ip,             default=true}
actions[8]  = {name="Cookie Server",                   func=read_ip,             default=true}
actions[9]  = {name="LPR Server",                      func=read_ip,             default=true}
actions[10] = {name="Impress Server",                  func=read_ip,             default=true}
actions[11] = {name="Resource Location Server",        func=read_ip,             default=true}
actions[12] = {name="Hostname",                        func=read_string,         default=true}
actions[13] = {name="Boot File Size",                  func=read_2_bytes,        default=false}
actions[14] = {name="Merit Dump File",                 func=read_string,         default=false}
actions[15] = {name="Domain Name",                     func=read_string,         default=true}
actions[16] = {name="Swap Server",                     func=read_ip,             default=true}
actions[17] = {name="Root Path",                       func=read_string,         default=false}
actions[18] = {name="Extensions Path",                 func=read_string,         default=false}
actions[19] = {name="IP Forwarding",                   func=read_boolean,        default=false}
actions[20] = {name="Non-local Source Routing",        func=read_boolean,        default=true}
actions[21] = {name="Policy Filter",                   func=read_policy_filter,  default=false}
actions[22] = {name="Maximum Datagram Reassembly Size",func=read_2_bytes,        default=false}
actions[23] = {name="Default IP TTL",                  func=read_1_byte,         default=false}
actions[24] = {name="Path MTU Aging Timeout",          func=read_time,           default=false}
actions[25] = {name="Path MTU Plateau",                func=read_2_bytes_list,   default=false}
actions[26] = {name="Interface MTU",                   func=read_2_bytes,        default=false}
actions[27] = {name="All Subnets are Local",           func=read_boolean,        default=false}
actions[28] = {name="Broadcast Address",               func=read_ip,             default=true}
actions[29] = {name="Perform Mask Discovery",          func=read_boolean,        default=false}
actions[30] = {name="Mask Supplier",                   func=read_boolean,        default=false}
actions[31] = {name="Perform Router Discovery",        func=read_boolean,        default=false}
actions[32] = {name="Router Solicitation Address",     func=read_ip,             default=true}
actions[33] = {name="Static Route",                    func=read_static_route,   default=true}
actions[34] = {name="Trailer Encapsulation",           func=read_boolean,        default=false}
actions[35] = {name="ARP Cache Timeout",               func=read_time,           default=false}
actions[36] = {name="Ethernet Encapsulation",          func=read_boolean,        default=false}
actions[37] = {name="TCP Default TTL",                 func=read_1_byte,         default=false}
actions[38] = {name="TCP Keepalive Interval",          func=read_4_bytes,        default=false}
actions[39] = {name="TCP Keepalive Garbage",           func=read_boolean,        default=false}
actions[40] = {name="NIS Domain",                      func=read_string,         default=true}
actions[41] = {name="NIS Servers",                     func=read_ip,             default=true}
actions[42] = {name="NTP Servers",                     func=read_ip,             default=true}
actions[43] = {name="Vendor Specific Information",     func=read_string,         default=false}
actions[44] = {name="NetBIOS Name Server",             func=read_ip,             default=true}
actions[45] = {name="NetBIOS Datagram Server",         func=read_ip,             default=true}
actions[46] = {name="NetBIOS Node Type",               func=read_1_byte,         default=false}
actions[47] = {name="NetBIOS Scope",                   func=read_string,         default=false}
actions[48] = {name="X Window Font Server",            func=read_ip,             default=true}
actions[49] = {name="X Window Display Manager",        func=read_ip,             default=true}
actions[50] = {name="Requested IP Address (client)",   func=read_ip,             default=false}
actions[51] = {name="IP Address Lease Time",           func=read_time,           default=false}
actions[52] = {name="Option Overload",                 func=read_1_byte,         default=false}
actions[53] = {name="DHCP Message Type",               func=read_message_type,   default=false}
actions[54] = {name="Server Identifier",               func=read_ip,             default=true}
actions[55] = {name="Parameter Request List (client)", func=read_string,         default=false}
actions[56] = {name="Error Message",                   func=read_string,         default=true}
actions[57] = {name="Maximum DHCP Message Size",       func=read_2_bytes,        default=false}
actions[58] = {name="Renewal Time Value",              func=read_time,           default=false}
actions[59] = {name="Rebinding Time Value",            func=read_time,           default=false}
actions[60] = {name="Class Identifier",                func=read_string,         default=false}
actions[61] = {name="Client Identifier (client)",      func=read_string,         default=false}



---Build a DHCP packet. 
--
--@param request_type    The type of request (such as DHCPINFORM). See the <code>request_types</code>
--                       table. 
--@param ip_address      The ip address (as a 4-byte string) where the server will send the response. 
--                       Generally, it'll be <code>host.bin_ip_src</code> or 255.255.255.255. 
--@param mac_address     The mac address (as a string no more than 16 bytes) where the server will 
--                       send the response. Generally, this will be <code>host.mac_addr_src</code> or
--                       simply a blank string (""). The field will be padded to 16 bytes with null bytes. 
--@param request_options [optional] The options to request from the server, as a string of bytes where each
--                       byte represents a single option. For the types of options, see rfc2132. Some DHCP
--                       servers (such as my Linksys WRT54g) will ignore this list and send whichever options
--                       it wants. Options won't necessarily be honoured, it's up to the server what it sends
--                       back. By default, all options (1..61) are requested. 
--@param overrides       [optional] A table of overrides. If a field in the table matches a field in the DHCP
--                       packet (see rfc2131 section 2 for a list of possible fields. Or, just look at the
--                       code.
--@param leasetime       [optional] The lease time for which to request an IP. Default: 1 second. 
--@return The packet, as a string. It should be sent to the server on UDP/67. 
local function dhcp_build(request_type, ip_address, mac_address, request_options, overrides, lease_time)
	local packet = ''

	if(overrides == nil) then
		overrides = {}
	end

	if(request_options == nil) then
		-- Request the defaults, or there's no verbosity; otherwise, request everything!
		request_options = ''
		for i = 1, 61, 1 do
			if(nmap.verbosity() > 0) then
				request_options = request_options .. string.char(i)
			else
				if(actions[i] and actions[i].default) then
					request_options = request_options .. string.char(i)
				end
			end
		end
	end

	-- Header
	packet = packet .. bin.pack(">CCCC", overrides['op'] or 1, overrides['htype'] or 1, overrides['hlen'] or 6, overrides['hops'] or 0)  -- BOOTREQUEST, 10mb ethernet, 6 bytes long, 0 hops
	packet = packet .. bin.pack(">I", overrides['xid'] or 0x4e4d4150)                            -- Transaction ID
	packet = packet .. bin.pack(">SS", overrides['secs'] or 0, overrides['flags'] or 0x0000)     -- Secs, flags
	packet = packet .. bin.pack("A", ip_address)                                                 -- Client address
	packet = packet .. bin.pack("<I", overrides['yiaddr'] or 0)                                  -- yiaddr
	packet = packet .. bin.pack("<I", overrides['siaddr'] or 0)                                  -- siaddr
	packet = packet .. bin.pack("<I", overrides['giaddr'] or 0)                                  -- giaddr
	packet = packet .. mac_address .. string.rep(string.char(0), 16 - #mac_address)              -- chaddr (MAC address)
	packet = packet .. (overrides['sname'] or string.rep(string.char(0), 64))                    -- sname
	packet = packet .. (overrides['file'] or string.rep(string.char(0), 128))                    -- file
	packet = packet .. bin.pack(">I", overrides['cookie'] or 0x63825363)                         -- Magic cookie

	-- Options
	packet = packet .. bin.pack(">CCC", 0x35, 1, request_type)                                   -- Request type
	packet = packet .. bin.pack(">CCA", 0x37, #request_options, request_options)                 -- Request options
	packet = packet .. bin.pack(">CCI", 0x33, 4, lease_time or 1)                                -- Lease time


	packet = packet .. bin.pack(">C", 0xFF)                                                      -- Termination

	return packet
end

---Parse a DHCP packet (either a request or a response) and return the results as a table. The
-- table at the top of this function (<code>actions</code>) defines the name of each field, as 
-- laid out in rfc2132, and the function that parses it. 
--
-- In theory, this should be able to parse any valid DHCP packet. 
--
--@param data The DHCP packet data. Any padding at the end of the packet will be ignored (by default, 
--            DHCP packets are padded with \x00 bytes). 
local function dhcp_parse(data)
	local pos = 1
	local result = {}

	-- Receive the first bit and make sure we got the correct operation back
	pos, result['op'], result['htype'], result['hlen'], result['hops'] = bin.unpack(">CCCC", data, pos)
	if(result['op'] ~= 2) then
		return false, string.format("DHCP server returned invalid reply ('op' wasn't BOOTREPLY (0x%02x))", result['op'])
	end

	-- Confirm the transaction id
	pos, result['xid'] = bin.unpack(">I", data, pos)
	if(result['xid'] ~= 0x4e4d4150) then
		return false, string.format("DHCP server returned invalid reply (transaction id didn't match (0x%08x != ))", result['xid'], 0x4e4d4150)
	end

	-- Unpack the secs, flags, addresses, sname, and file
	pos, result['secs'], result['flags'] = bin.unpack(">SS", data, pos)
	pos, result['ciaddr'] = bin.unpack("<I", data, pos)
	pos, result['yiaddr'] = bin.unpack("<I", data, pos)
	pos, result['siaddr'] = bin.unpack("<I", data, pos)
	pos, result['giaddr'] = bin.unpack("<I", data, pos)
	pos, result['chaddr'] = bin.unpack("A16", data, pos)
	pos, result['sname']  = bin.unpack("A64", data, pos)
	pos, result['file']   = bin.unpack("A128", data, pos)

	-- Convert the addresses to strings
	result['ciaddr_str'] = ipOps.fromdword(result['ciaddr'])
	result['yiaddr_str'] = ipOps.fromdword(result['yiaddr'])
	result['siaddr_str'] = ipOps.fromdword(result['siaddr'])
	result['giaddr_str'] = ipOps.fromdword(result['giaddr'])

	-- Confirm the cookie
	pos, result['cookie'] = bin.unpack(">I", data, pos)
	if(result['cookie'] ~= 0x63825363) then
		return false, "DHCP server returned invalid reply (the magic cookie was invalid)"
	end

	-- Parse the options
	result['options'] = {}
	while true do
		local option, length
		pos, option, length = bin.unpack(">CC", data, pos)

		-- Check for termination condition
		if(option == 0xFF) then
			break;
		end

		-- Get the action from the array, based on the code
		local action = actions[option]

		-- Verify we got a valid code (if we didn't, we're probably in big trouble)
		if(action == nil) then
			stdnse.print_debug("dhcp-discover: Unknown option: %d", option)
			pos = pos + length
		else
			-- Call the function to parse the option, and insert the result into our results table
			pos, value = action['func'](data, pos, length)

			if(nmap.verbosity() == 0 and action.default == false) then
				stdnse.print_debug(1, "dhcp-discover: Server returned unrequested option (%s => %s)", action['name'], value)

			else
				table.insert(result['options'], {name=action['name'], value=value})
			end
		end

		-- Handle the 'Option Overload' option specially -- if it's set, it tells us to use the file and/or sname values after we
		-- run out of data. 
		if(option == 52) then
			if(value == 1) then
				data = data .. result['file']
			elseif(value == 2) then
				data = data .. result['sname']
			elseif(value == 3) then
				data = data .. result['file'] .. result['sname']
			else
				stdnse.print_debug(1, "dhcp-discover: Warning: 'Option Overload' gave an unsupported value: %d", value)
			end
		end
	end

	return true, result
end

local function go(host, port)
	local pcap, socket
	local status, err, data
	local result
	local results = {}

	local timeout = 5000
	if(nmap.registry.args.timeout) then
		timeout = tonumber(nmap.registry.args.timeout)
	end

	local requests = 1
	if(nmap.registry.args.requests) then
		requests = tonumber(nmap.registry.args.requests)
	end

	-- Verify we have a IPv4 address
	if(string.len(host.bin_ip_src) ~= 4) then
		return false, "Sorry, dhcp-discover only supports IPv4!"
	end

	-- Verify we have a MAC address
	if(string.len(host.mac_addr_src) ~= 6) then
		return false, "Sorry, dhcp-discover only supports Ethernet!"
	end

	-- Create a pcap socket to listen for the response (this is a HUGE hack. TODO: Fix once I can set the source port)
	pcap = nmap.new_socket()
	pcap:pcap_open(host.interface, 590, 0, callback, "udp port 68")
	stdnse.print_debug("dhcp-discover: Setting socket timeout to %ds", timeout)
	pcap:set_timeout(timeout)

	-- Create the UDP socket
	socket = nmap.new_socket()
	status, err = socket:connect(host.ip, port.number, "udp")
	if(status == false) then
		return false, "Couldn't create socket: " .. err
	end

	-- We're going to need some low quality random numbers
	math.randomseed(os.time())

	-- Create fake requests if the user asked to. These are fired and forgotten, we ignore the responses. 
	if(nmap.registry.args.fake_requests) then
		for i=1, tonumber(nmap.registry.args.fake_requests), 1 do
			-- Build and send a DHCP request using the specified request type, or DHCPDISCOVER
			local request_type = request_types[nmap.registry.args.dhcptype or "DHCPDISCOVER"]
			if(request_type == nil) then
				return false, "Valid request types: " .. stdnse.strjoin(", ", request_types_str)
			end

			-- Generate the MAC address, if it's random
			local mac_addr = host.mac_addr_src
			if(nmap.registry.args.randomize_mac == 'true' or nmap.registry.args.randomize_mac == '1') then
				stdnse.print_debug(2, "dhcp-discover: Generating a random MAC address")
				mac_addr = ""
				for j=1, 6, 1 do
					mac_addr = mac_addr .. string.char(math.random(1, 255))
				end
			end

			-- Build and send the packet
			local response = dhcp_build(request_type, host.bin_ip_src, mac_addr, nil, {xid=i})
			socket:send(response)

		end
	end

	-- Build and send a DHCP request using the specified request type, or DHCPDISCOVER
	for i = 1, requests, 1 do
		-- Register the packet cap
		pcap:pcap_register("NMAP")

		-- Decide which type of request to make
		local request_type = request_types[nmap.registry.args.dhcptype or "DHCPDISCOVER"]
		if(request_type == nil) then
			return false, "Valid request types: " .. stdnse.strjoin(", ", request_types_str)
		end
	
		-- Generate the MAC address, if it's random
		local mac_addr = host.mac_addr_src
		if(nmap.registry.args.randomize_mac == 'true' or nmap.registry.args.randomize_mac == '1') then
			stdnse.print_debug(2, "dhcp-discover: Generating a random MAC address")
			mac_addr = ""
			for j=1, 6, 1 do
				mac_addr = mac_addr .. string.char(math.random(1, 255))
			end
		end
	
		-- Build and send the packet
		stdnse.print_debug(2, "dhcp-discover: Sending DHCP request #%d", i)
		local response = dhcp_build(request_type, host.bin_ip_src, mac_addr)
		socket:send(response)

		-- Receive the result
		status, err, _, data = pcap:pcap_receive()
		if(status == false) then
			stdnse.print_debug(1, "dhcp-discover: Error calling pcap_receive(): %s", err)
			return false, "Error calling pcap_receive(): " .. err
		end

		-- If no data was captured (ie, a timeout), return what, if anything, we have	
		if(data == nil) then
			stdnse.print_debug(1, "dhcp-discover: Error calling pcap_receive(): TIMEOUT")
			if(#results > 0) then
				return true, results
			else
				return false, "Error calling pcap_receive(): TIMEOUT"
			end
		end

		-- Cut off the address/transport headers
		data = string.sub(data, 29) -- I doubt this is the right way to do this, but since we're only supporting IPv4 + UDP, maybe it'll work?
	
		-- Parse the result
		
		status, result = dhcp_parse(data)
		if(status == false) then
			stdnse.print_debug(1, "dhcp-discover: Couldn't parse DHCP packet: %s", result)
			return false, "Couldn't parse DHCP packet: " .. result
		end

		table.insert(results, result)
	end
	socket:close()

	-- Done!
	return true, results
end

action = function(host, port)
	local status, results = go(host, port)

	if(status == false) then
		return stdnse.format_output(false, results)
	end

	if(results == nil) then
		return nil
	end

	-- Set the port state to open
	nmap.set_port_state(host, port, "open")

	local response = {}

	-- Display the results
	for i, result in ipairs(results) do
		if(#results ~= 1) then
			table.insert(response, string.format("Result %d", i))
		end

		table.insert(response, string.format("IP Offered: %s", result.yiaddr_str))
		for _, v in ipairs(result.options) do
			if(type(v['value']) == 'table') then
				table.insert(response, string.format("%s: %s", v['name'], stdnse.strjoin(", ", v['value'])))
			else
				table.insert(response, string.format("%s: %s\n", v['name'], v['value']))
			end
		end
	end

	return stdnse.format_output(true, response)
end




