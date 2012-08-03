local nmap = require "nmap"
local packet = require "packet"
local ipOps = require "ipOps"
local bin = require "bin"
local stdnse = require "stdnse"
local target = require "target"
local table = require "table"


description = [[
Queries a target router for multicast information.

This works by sending a DVMRP Ask Neighbors 2 request to the target and
listening for the DVMRP Neighbors 2 response that contains local addresses and
the multicast neighbors on each one.

]]


---
-- @args mrinfo.timeout Time to wait for a response in seconds.
-- Defaults to <code>5</code> seconds.
--
--@usage
-- nmap --script mrinfo <target>
--
--@output
-- Host script results:
-- | mrinfo: 
-- |   Version 12.4
-- |   Local address: 192.168.2.2
-- |     Neighbor: 192.168.2.4
-- |     Neighbor: 192.168.2.3
-- |   Local address: 192.168.13.1
-- |     Neighbor: 192.168.13.3
-- |_  Use the newtargets script-arg to add the results as targets


author = "Hani Benhabiles"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


hostrule = function(host) 
    if nmap.address_family() ~= 'inet' then
	stdnse.print_verbose("%s is IPv4 only.", SCRIPT_NAME)
	return false
    end
    return true
end

-- Parses a DVMRP Ask Neighbor 2 raw data and returns
-- a structured response.
-- @param data raw data.
local mrinfoParse = function(data)
    local index, interface, neighbor
    local response = {}

    -- first byte should be IGMP type == 0x013 (DVMRP)
    if data:byte(1) ~= 0x013 then return end

    -- DVMRP Code
    index, response.code = bin.unpack(">C", data, 2)
    -- Checksum
    index, response.checksum = bin.unpack(">S", data, index)
    -- Capabilities (Skip one reserved byte)
    index, response.capabilities = bin.unpack(">C", data, index + 1)
    -- Major and minor version
    index, response.minver = bin.unpack(">C", data, index)
    index, response.majver = bin.unpack(">C", data, index)
    response.interfaces = {}
    -- Iterate over target local addresses (interfaces)
    while index < #data do
	if data:byte(index) == 0x00 then break end
	interface = {}
	-- Local address
	index, interface.address = bin.unpack("<I", data, index)
	interface.address = ipOps.fromdword(interface.address)
	-- Link metric
	index, interface.metric = bin.unpack(">C", data, index)
	-- Treshold
	index, interface.treshold= bin.unpack(">C", data, index)
	-- Flags
	index, interface.flags = bin.unpack(">C", data, index)
	-- Number of neighbors 
	index, interface.ncount = bin.unpack(">C", data, index)

	interface.neighbors = {}
	-- Iterate over neighbors
	for i = 1, interface.ncount do
	    index, neighbor = bin.unpack("<I", data, index)
	    table.insert(interface.neighbors, ipOps.fromdword(neighbor))
	end
	table.insert(response.interfaces, interface)
    end
    return response
end

-- Listens for DVMRP Ask Neighbors 2 responses
--@param interface Network interface to listen on.
--@param host Host table as commonly used in Nmap.
--@param timeout Time to listen for a response.
--@param results table to put response into.
local mrinfoListen = function(interface, host, timeout, results)
    local condvar = nmap.condvar(results)
    local start = nmap.clock_ms()
    local listener = nmap.new_socket()
    local p, mrinfo_raw, status, l3data, response
    -- IGMP packets that are sent from the target host to our host.
    local filter = 'ip proto 2 and src host ' .. host.ip .. ' and dst host ' .. interface.address

    listener:set_timeout(100)
    -- IP proto 0x02 == IGMP
    listener:pcap_open(interface.device, 1024, true, filter)

    while (nmap.clock_ms() - start) < timeout do
	status, _, _, l3data = listener:pcap_receive()
	if status then
	    p = packet.Packet:new(l3data, #l3data)
	    mrinfo_raw = string.sub(l3data, p.ip_hl*4 + 1)
	    if p then
		-- Check that IGMP Type == DVMRP (0x13) and DVMRP code == Neighbor 2 (0x06)
		if mrinfo_raw:byte(1) == 0x13 and mrinfo_raw:byte(2) == 0x06 then
		    response = mrinfoParse(mrinfo_raw)
		    if response then 
			table.insert(results, response)
			break
		    end
		end
	    end
	end
    end
    condvar("signal")
end

-- Function that generates a raw DVMRP Ask Neighbors 2 request.
local mrinfoRaw = function()
    -- Type: DVMRP
    local mrinfo_raw = bin.pack(">C", 0x13)
    -- Code: Ask Neighbor v2
    mrinfo_raw = mrinfo_raw.. bin.pack(">C", 0x05)
    -- Checksum: Calculated later
    mrinfo_raw = mrinfo_raw.. bin.pack(">S", 0x0000)
    -- Reserved
    mrinfo_raw = mrinfo_raw.. bin.pack(">S", 0x000a)
    -- Version == Cisco IOS 12.4
    -- Minor version: 4
    mrinfo_raw = mrinfo_raw.. bin.pack(">C", 0x04)
    -- Major version: 12
    mrinfo_raw = mrinfo_raw.. bin.pack(">C", 0x0c)
    -- Calculate checksum
    mrinfo_raw = mrinfo_raw:sub(1,2) .. bin.pack(">S", packet.in_cksum(mrinfo_raw)) .. mrinfo_raw:sub(5)

    return mrinfo_raw 
end

-- Function that sends a DVMRP query.
--@param mrinfo_raw Raw DVMRP packet.
--@param scrip Source IP of the packet.
--@param dstip Destination IP to send to.
local mrinfoQuery = function(mrinfo_raw, srcip, dstip)

    local ip_raw = bin.pack("H", "45c00040ed780000400218bc0a00c8750a00c86b") .. mrinfo_raw -- Less ugly way to do it ?
    local mrinfo_packet = packet.Packet:new(ip_raw, ip_raw:len())
    mrinfo_packet:ip_set_bin_src(ipOps.ip_to_str(srcip))
    mrinfo_packet:ip_set_bin_dst(ipOps.ip_to_str(dstip))
    mrinfo_packet:ip_set_len(ip_raw:len())

    local sock = nmap.new_dnet()
    sock:ip_open()
    sock:ip_send(mrinfo_packet.buf)
    sock:ip_close()
end


action = function(host)
    local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
    local mrinfo_raw, dstip, srcip, interface
    local results = {}

    timeout = timeout * 1000

    dstip = host.ip
    interface = nmap.get_interface_info(host.interface)
    srcip = interface.address

    -- Thread that listens for responses
    stdnse.new_thread(mrinfoListen, interface, host, timeout, results)

    -- Send request
    stdnse.sleep(0.5)
    mrinfo_raw = mrinfoRaw()
    mrinfoQuery(mrinfo_raw, srcip, dstip)
    local condvar = nmap.condvar(results)
    condvar("wait")

    if #results > 0 then
	local output, ifoutput = {}
	local response = results[1]
	table.insert(output, ("Version %s.%s"):format(response.majver, response.minver))
	for _, interface in pairs(response.interfaces) do
	    ifoutput = {}
	    ifoutput.name = "Local address: " .. interface.address
	    for _, neighbor in pairs(interface.neighbors) do
		if target.ALLOW_NEW_TARGETS then target.add(neighbor) end
		table.insert(ifoutput, "Neighbor: " .. neighbor)
	    end
	    table.insert(output, ifoutput)
	end
	if not target.ALLOW_NEW_TARGETS then
	    table.insert(output,"Use the newtargets script-arg to add the results as targets")
	end
	return stdnse.format_output(true, output)
    end
end
