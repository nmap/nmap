local eigrp = require "eigrp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local packet = require "packet"
local ipOps = require "ipOps"
local target = require "target"
local coroutine = require "coroutine"
local string = require "string"

description = [[
Performs network discovery and routing information gathering through
Cisco's Enhanced Interior Gateway Routing Protocol (EIGRP).

The script works by sending an EIGRP Hello packet with the specified Autonomous
System value to the 224.0.0.10 multicast address and listening for EIGRP Update
packets. The script then parses the update responses for routing information.

If no A.S value was provided by the user, the script will listen for multicast
Hello packets to grab an A.S value. If no interface was provided as a script
argument or through the -e option, the script will send packets and listen
through all valid ethernet interfaces simultaneously.

]]

---
-- @usage
-- nmap --script=broadcast-eigrp-discovery <targets>
-- nmap --script=broadcast-eigrp-discovery <targets> -e wlan0
--
-- @args broadcast-eigrp-discovery.as Autonomous System value to announce on.
-- If not set, the script will listen for announcements on 224.0.0.10 to grab
-- an A.S value.
--
-- @args broadcast-eigrp-discovery.timeout Max amount of time to listen for A.S
-- announcements and updates. Defaults to <code>10</code> seconds.
--
-- @args broadcast-eigrp-discovery.kparams the K metrics. 
-- Defaults to <code>101000</code>.
-- @args broadcast-eigrp-discovery.interface Interface to send on (overrides -e)
--
--@output
-- Pre-scan script results:
-- | broadcast-eigrp-discovery:
-- | 192.168.2.2
-- |   Interface: eth0 
-- |   A.S: 1
-- |   Virtual Router ID: 0
-- |   Internal Route
-- |     Destination: 192.168.21.0/24
-- |     Next hop: 0.0.0.0
-- |   Internal Route
-- |     Destination: 192.168.31.0/24
-- |     Next hop: 0.0.0.0
-- |   External Route
-- |     Protocol: Static
-- |     Originating A.S: 0
-- |     Originating Router ID: 192.168.31.1
-- |     Destination: 192.168.60.0/24
-- |     Next hop: 0.0.0.0
-- |   External Route
-- |     Protocol: OSPF
-- |     Originating A.S: 1
-- |     Originating Router ID: 192.168.31.1
-- |     Destination: 192.168.24.0/24
-- |     Next hop: 0.0.0.0
-- |_  Use the newtargets script-arg to add the results as targets
--

author = "Hani Benhabiles"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "broadcast", "safe"}

prerule = function()
    if nmap.address_family() ~= 'inet' then
	stdnse.print_verbose("%s is IPv4 only.", SCRIPT_NAME)
	return false
    end
    if not nmap.is_privileged() then
	stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
	return false
    end
    return true
end


-- Sends EIGRP raw packet to EIGRP multicast address.
--@param interface Network interface to use.
--@param eigrp_raw Raw eigrp packet.
local eigrpSend = function(interface, eigrp_raw)
    local srcip = interface.address
    local dstip = "224.0.0.10"

    local ip_raw = bin.pack("H", "45c00040ed780000015818bc0a00c8750a00c86b") .. eigrp_raw
    local eigrp_packet = packet.Packet:new(ip_raw, ip_raw:len())
    eigrp_packet:ip_set_bin_src(ipOps.ip_to_str(srcip))
    eigrp_packet:ip_set_bin_dst(ipOps.ip_to_str(dstip))
    eigrp_packet:ip_set_len(#eigrp_packet.buf)
    eigrp_packet:ip_count_checksum()

    local sock = nmap.new_dnet()
    sock:ethernet_open(interface.device)
    -- Ethernet IPv4 multicast, our ethernet address and packet type IP
    local eth_hdr = bin.pack("HAH", "01 00 5e 00 00 0a", interface.mac, "08 00")
    sock:ethernet_send(eth_hdr .. eigrp_packet.buf)
    sock:ethernet_close()
end


-- Listens for EIGRP updates
--@param interface Network interface to listen on.
--@param timeout Ammount of time to listen for.
--@param responses Table to put valid responses into.
local eigrpListener = function(interface, timeout, responses)
    local condvar = nmap.condvar(responses)
    local routers = {}
    local status, l3data, response, p, eigrp_raw, _
    local start = nmap.clock_ms()
    -- Filter for EIGRP packets that are sent either to us or to multicast
    local filter =  "ip proto 88 and (ip dst host " .. interface.address .. " or 224.0.0.10)"
    local listener = nmap.new_socket()
    listener:set_timeout(500)
    listener:pcap_open(interface.device, 1024, true, filter)

    -- For each EIGRP packet captured until timeout
    while (nmap.clock_ms() - start) < timeout do
	response = {}
	response.tlvs = {}
	status, _, _, l3data = listener:pcap_receive()
	if status then
	    p = packet.Packet:new(l3data, #l3data)
	    eigrp_raw = string.sub(l3data, p.ip_hl*4 + 1)
	    -- Check if it is an EIGRPv2 Update 
	    if eigrp_raw:byte(1) == 0x02 and eigrp_raw:byte(2) == 0x01 then
		-- Skip if did get the info from this router before
		if not routers[p.ip_src] then
		    -- Parse header
		    response = eigrp.EIGRP.parse(eigrp_raw)
		    response.src = p.ip_src
		    response.interface = interface.shortname
		end
		if response then
		    -- See, if it has routing information
		    for _,tlv in pairs(response.tlvs) do
			if eigrp.EIGRP.isRoutingTLV(tlv.type) then
			    routers[p.ip_src] = true
			    table.insert(responses, response)
			    break
			end
		    end
		end
	    end
	end
    end
    condvar("signal")
    return
end

-- Listens for EIGRP announcements to grab a valid Autonomous System value.
--@param interface Network interface to listen on.
--@param timeout Max amount of time to listen for.
--@param astab Table to put result into.
local asListener = function(interface, timeout, astab)
    local condvar = nmap.condvar(astab)
    local status, l3data, p, eigrp_raw, eigrp_hello, _
    local start = nmap.clock_ms()
    local filter =  "ip proto 88 and ip dst host 224.0.0.10"
    local listener = nmap.new_socket()
    listener:set_timeout(500)
    listener:pcap_open(interface.device, 1024, true, filter)
    while (nmap.clock_ms() - start) < timeout do
	-- Check if another listener already found an A.S value.
	if #astab > 0 then break end

	status, _, _, l3data = listener:pcap_receive()
	if status then
	    p = packet.Packet:new(l3data, #l3data)
	    eigrp_raw = string.sub(l3data, p.ip_hl*4 + 1)
	    -- Listen for EIGRPv2 Hello packets
	    if eigrp_raw:byte(1) == 0x02 and eigrp_raw:byte(2) == 0x05 then
		eigrp_hello = eigrp.EIGRP.parse(eigrp_raw)
		if eigrp_hello and eigrp_hello.as then
		    table.insert(astab, eigrp_hello.as)
		    break
		end
	    end
	end
    end
    condvar("signal")
end

action = function()
    -- Get script arguments
    local as = stdnse.get_script_args(SCRIPT_NAME .. ".as")
    local kparams = stdnse.get_script_args(SCRIPT_NAME .. ".kparams") or "101000"
    local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
    local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
    local output, responses, interfaces, lthreads = {}, {}, {}, {}
    local result, response, route, eigrp_hello, k
    local timeout = (timeout or 10) * 1000

    -- K params should be of length 6
    -- Cisco routers ignore eigrp packets that don't have matching K parameters
    if #kparams < 6 or #kparams > 6 then
	return "\n ERROR: kparams should be of size 6."
    else
	k = {}
	k[1] = string.sub(kparams, 1,1)
	k[2] = string.sub(kparams, 2,2)
	k[3] = string.sub(kparams, 3,3)
	k[4] = string.sub(kparams, 4,4)
	k[5] = string.sub(kparams, 5,5)
	k[6] = string.sub(kparams, 6)
    end

    interface = interface or nmap.get_interface()
    if interface then
	-- If an interface was provided, get its information
	interface = nmap.get_interface_info(interface)
	if not interface then
	    return ("\n ERROR: Failed to retreive %s interface information."):format(interface)
	end
	interfaces = {interface}
	stdnse.print_debug("%s: Will use %s interface.", SCRIPT_NAME, interface.shortname)
    else
	local ifacelist = nmap.list_interfaces()
	for _, iface in ipairs(ifacelist) do
	    -- Match all ethernet interfaces
	    if iface.address and iface.link=="ethernet" and 
		iface.address:match("%d+%.%d+%.%d+%.%d+") then

		stdnse.print_debug("%s: Will use %s interface.", SCRIPT_NAME, iface.shortname)
		table.insert(interfaces, iface)
	    end
	end
    end

    -- If user didn't provide an Autonomous System value, we listen fro multicast
    -- HELLO router announcements to get one.
    if not as then
	-- We use a table for condvar
	local astab = {}
	stdnse.print_debug("%s: No A.S value provided, will sniff for one.", SCRIPT_NAME)
	-- We should iterate over interfaces
	for _, interface in pairs(interfaces) do
	    local co = stdnse.new_thread(asListener, interface, timeout, astab)
	    lthreads[co] = true
	end
	local condvar = nmap.condvar(astab)
	-- Wait for the listening threads to finish
	repeat
		for thread in pairs(lthreads) do
			if coroutine.status(thread) == "dead" then lthreads[thread] = nil end
	  end
		if ( next(lthreads) ) then
			condvar("wait")
		end
	until next(lthreads) == nil;

	if #astab > 0 then
	    stdnse.print_debug("Will use %s A.S value.", astab[1])
	    as = astab[1]
	else
	    return "\n ERROR: Couldn't get an A.S value."
	end
    end

    -- Craft Hello packet
    eigrp_hello = eigrp.EIGRP:new(eigrp.OPCODE.HELLO, as)
    -- K params
    eigrp_hello:addTLV({ type = eigrp.TLV.PARAM, k = k, htime = 15})
    -- Software version
    eigrp_hello:addTLV({ type = eigrp.TLV.SWVER, majv = 12, minv = 4, majtlv = 1, mintlv = 2})

    -- On each interface, launch the listening thread and send the Hello packet.
    lthreads = {}
    for _, interface in pairs(interfaces) do
	local co = stdnse.new_thread(eigrpListener, interface, timeout, responses)
	-- We insert a small delay before sending the Hello so the listening
	-- thread doesn't miss updates.
	stdnse.sleep(0.5)
	lthreads[co] = true
	eigrpSend(interface, tostring(eigrp_hello))
    end

    local condvar = nmap.condvar(responses)
    -- Wait for the listening threads to finish
    repeat
	condvar("wait")
	for thread in pairs(lthreads) do
	    if coroutine.status(thread) == "dead" then lthreads[thread] = nil end
	end
    until next(lthreads) == nil;

    -- Output the useful info from the responses
    if #responses > 0 then
	for _, response in pairs(responses) do
	    result = {}
	    result.name = response.src
	    if target.ALLOW_NEW_TARGETS then target.add(response.src) end
	    table.insert(result, "Interface: " .. response.interface)
	    table.insert(result, ("A.S: %d"):format(response.as))
	    table.insert(result, ("Virtual Router ID: %d"):format(response.routerid))
	    -- Output routes information TLVs
	    for _, tlv in pairs(response.tlvs) do
		route = {}
		-- We are only interested in Internal or external routes
		if tlv.type == eigrp.TLV.EXT then
		    route.name = "External route"
		    for name, value in pairs(eigrp.EXT_PROTO) do
			if value == tlv.eproto then
			    table.insert(route, ("Protocol: %s"):format(name))
			    break
			end
		    end
		    table.insert(route, ("Originating A.S: %s"):format(tlv.oas))
		    table.insert(route, ("Originating Router ID: %s"):format(tlv.orouterid))
		    if target.ALLOW_NEW_TARGETS then target.add(tlv.orouterid) end
		    table.insert(route, ("Destination: %s/%d"):format(tlv.dst, tlv.mask))
		    table.insert(route, ("Next hop: %s"):format(tlv.nexth))
		    table.insert(result, route)
		elseif tlv.type == eigrp.TLV.INT then
		    route.name = "Internal route"
		    table.insert(route, ("Destination: %s/%d"):format(tlv.dst, tlv.mask))
		    table.insert(route, ("Next hop: %s"):format(tlv.nexth))
		    table.insert(result, route)
		end
	    end
	    table.insert(output, result)
	end
	if #output>0 and not target.ALLOW_NEW_TARGETS then
	    table.insert(output,"Use the newtargets script-arg to add the results as targets")
	end
	return stdnse.format_output(true, output)
    end
end
