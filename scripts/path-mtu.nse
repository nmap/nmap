description = [[
Performs simple Path MTU Discovery to target hosts.

TCP or UDP packets are sent to the host with the DF (don't fragment) bit
set and with varying amounts of data.  If an ICMP Fragmentation Needed
is received, or no reply is received after retransmissions, the amount
of data is lowered and another packet is sent.  This continues until
(assuming no errors occur) a reply from the final host is received,
indicating the packet reached the host without being fragmented.

Not all MTUs are attempted so as to not expend too much time or network
resources.  Currently the relatively short list of MTUs to try contains
the plateau values from Table 7-1 in RFC 1191, "Path MTU Discovery".
Using these values significantly cuts down the MTU search space.  On top
of that, this list is rarely traversed in whole because:
    * the MTU of the outgoing interface is used as a starting point, and
    * we can jump down the list when an intermediate router sending a
      "can't fragment" message includes its next hop MTU (as described
      in RFC 1191 and required by RFC 1812) 
]]

---
-- @usage 
-- nmap --script path-mtu target
--
-- @output
-- Host script results:
-- |_path-mtu: 1492 <= PMTU < 1500
--
-- Host script results:
-- |_path-mtu: PMTU == 1006

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

require 'bin'
require 'packet'
require 'nmap'
require 'stdnse'

local IPPROTO_ICMP = packet.IPPROTO_ICMP
local IPPROTO_TCP  = packet.IPPROTO_TCP
local IPPROTO_UDP  = packet.IPPROTO_UDP

-- Number of times to retransmit for no reply before dropping to
-- another MTU value
local RETRIES = 1

-- RFC 1191, Table 7-1: Plateaus. Even the massive MTU values are
-- here since we skip down the list based on the outgoing interface
-- so its no harm.
local MTUS = {
	65535,
	32000,
	17914,
	8166,
	4352,
	2002,
	1492,
	1006,
	508,
	296,
	68
}

-- Find the index in MTUS{} to use based on the MTU +new+. If +new+ is in
-- between values in MTUS, then insert it into the table appropriately.
local searchmtu = function(cidx, new)
	if new == 0 then
		return cidx
	end

	while cidx <= #MTUS do
		if new >= MTUS[cidx] then
			if new ~= MTUS[cidx] then
				table.insert(MTUS, cidx, new)
			end
			return cidx
		end
		cidx = cidx + 1
	end
	return cidx
end

local dport = function(ip)
	if ip.ip_p == IPPROTO_TCP then
		return ip.tcp_dport
	elseif ip.ip_p == IPPROTO_UDP then
		return ip.udp_dport
	end
end

local sport = function(ip)
	if ip.ip_p == IPPROTO_TCP then
		return ip.tcp_sport
	elseif ip.ip_p == IPPROTO_UDP then
		return ip.udp_sport
	end
end

-- Checks how we should react to this packet
local checkpkt = function(reply, orig)
	local ip = packet.Packet:new(reply, reply:len())

	if ip.ip_p == IPPROTO_ICMP then
		if ip.icmp_type ~= 3 then
			return "recap"
		end
		-- Port Unreachable
		if ip.icmp_code == 3 then
			local is = ip.buf:sub(ip.icmp_offset + 9)
			local ip2 = packet.Packet:new(is, is:len())

			-- Check sent packet against ICMP payload
			if ip2.ip_p ~= IPPROTO_UDP or
			   ip2.ip_p ~= orig.ip_p or
			   ip2.ip_bin_src ~= orig.ip_bin_src or
			   ip2.ip_bin_dst ~= orig.ip_bin_dst or
			   sport(ip2) ~= sport(orig) or
			   dport(ip2) ~= dport(orig) then
				return "recap"
			end

			return "gotreply"
		end
		-- Frag needed, DF set
		if ip.icmp_code == 4 then
			local val = ip:u16(ip.icmp_offset + 6)
			return "nextmtu", val
		end
		return "recap"
	end

	if ip.ip_p ~= orig.ip_p or
	   ip.ip_bin_src ~= orig.ip_bin_dst or
	   ip.ip_bin_dst ~= orig.ip_bin_src or
	   dport(ip) ~= sport(orig) or
	   sport(ip) ~= dport(orig) then
		return "recap"
	end

	return "gotreply"
end

-- This is all we can use since we can get various protocols back from
-- different hosts
local check = function(layer3)
	local ip = packet.Packet:new(layer3, layer3:len())
	return bin.pack('A', ip.ip_bin_dst)
end

-- Updates a packet's info and calculates checksum
local updatepkt = function(ip)
	if ip.ip_p == IPPROTO_TCP then
		ip:tcp_set_sport(math.random(0x401, 0xffff))
		ip:tcp_set_seq(math.random(1, 0x7fffffff))
		ip:tcp_count_checksum()
	elseif ip.ip_p == IPPROTO_UDP then
		ip:udp_set_sport(math.random(0x401, 0xffff))
		ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
		ip:udp_count_checksum()
	end
	ip:ip_count_checksum()
end

-- Set up packet header and data to satisfy a certain MTU
local setmtu = function(pkt, mtu)
	if pkt.ip_len < mtu then
		pkt.buf = pkt.buf .. string.rep("\0", mtu - pkt.ip_len)
	else
		pkt.buf = pkt.buf:sub(1, mtu)
	end

	pkt:ip_set_len(mtu)
	pkt.packet_length = mtu
	updatepkt(pkt)
end

local basepkt = function(proto)
	local ibin = bin.pack("H",
		"4500 0014 0000 4000 8000 0000 0000 0000 0000 0000"
	)
	local tbin = bin.pack("H",
		"0000 0000 0000 0000 0000 0000 6002 0c00 0000 0000 0204 05b4"
	)
	local ubin = bin.pack("H",
		"0000 0000 0800 0000"
	)

	if proto == IPPROTO_TCP then
		return ibin .. tbin
	elseif proto == IPPROTO_UDP then
		return ibin .. ubin
	end
end

-- Creates a Packet object for the given proto and port
local genericpkt = function(host, proto, port)
	local pkt = basepkt(proto)
	local ip = packet.Packet:new(pkt, pkt:len())

	ip:ip_set_bin_src(host.bin_ip_src)
	ip:ip_set_bin_dst(host.bin_ip)

	ip:set_u8(ip.ip_offset + 9, proto)
	ip.ip_p = proto

	ip:ip_set_len(pkt:len())

	if proto == IPPROTO_TCP then
		ip:tcp_parse(false)
		ip:tcp_set_dport(port)
	elseif proto == IPPROTO_UDP then
		ip:udp_parse(false)
		ip:udp_set_dport(port)
	end

	updatepkt(ip)

	return ip
end

local ipproto = function(p)
	if p == "tcp" then
		return IPPROTO_TCP
	elseif p == "udp" then
		return IPPROTO_UDP
	end
	return -1
end

-- Determines how to probe
local getprobe = function(host)
	local combos = {
		{ "tcp", "open" },
		{ "tcp", "closed" },
		-- udp/open probably only happens when Nmap sends proper
		-- payloads, which doesn't happen in here
		{ "udp", "closed" }
	}
	local proto = nil
	local port = nil

	for _, c in ipairs(combos) do
		port = nmap.get_ports(host, nil, c[1], c[2])
		if port then
			proto = c[1]
			break
		end
	end

	return proto, port
end

-- Sets necessary probe data in registry
local setreg = function(host, proto, port)
	if not nmap.registry[host.ip] then
		nmap.registry[host.ip] = {}
	end
	nmap.registry[host.ip]['pathmtuprobe'] = {
		['proto'] = proto,
		['port'] = port
	}
end

hostrule = function(host)
	if not nmap.is_privileged() then
		if not nmap.registry['pathmtu'] then
			nmap.registry['pathmtu'] = {}
		end
		if nmap.registry['pathmtu']['rootfail'] then
			return false
		end
		nmap.registry['pathmtu']['rootfail'] = true
		if nmap.verbosity() > 0 then
			stdnse.print_debug("%s not running for lack of privileges.", SCRIPT_NAME)
		end
		return false
	end
	if nmap.address_family() ~= 'inet' then
		stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
		return false
	end
	if not (host.interface and host.interface_mtu) then
		return false
	end
	local proto, port = getprobe(host)
	if not (proto and port) then
		return false
	end
	setreg(host, proto, port.number)
	return true
end

action = function(host)
	local m, r
	local gotit = false
	local mtuset
	local sock = nmap.new_dnet()
	local pcap = nmap.new_socket()
	local proto = nmap.registry[host.ip]['pathmtuprobe']['proto']
	local port = nmap.registry[host.ip]['pathmtuprobe']['port']
	local saddr = packet.toip(host.bin_ip_src)
	local daddr = packet.toip(host.bin_ip)
	local try = nmap.new_try()
	local status, pkt, ip

	try(sock:ip_open())

	try = nmap.new_try(function() sock:ip_close() end)

	pcap:pcap_open(host.interface, 104, false, "dst host " .. saddr .. " and (icmp or (" .. proto .. " and src host " .. daddr .. " and src port " .. port .. "))")

	-- Since we're sending potentially large amounts of data per packet,
	-- simply bump up the host's calculated timeout value.  Most replies
	-- should come from routers along the path, fragmentation reassembly
	-- times isn't an issue and the large amount of data is only travelling
	-- in one direction; still, we want a response from the target so call
	-- it 1.5*timeout to play it safer.
	pcap:set_timeout(1.5 * host.times.timeout * 1000)

	m = searchmtu(1, host.interface_mtu)

	mtuset = MTUS[m]

	local pkt = genericpkt(host, ipproto(proto), port)

	while m <= #MTUS do
		setmtu(pkt, MTUS[m])

		r = 0
		status = false
		while true do
			if not status then
				if not sock:ip_send(pkt.buf) then
					-- Got a send error, perhaps EMSGSIZE
					-- when we don't know our interface's
					-- MTU.  Drop an MTU and keep trying.
					break
				end
			end

			local test = bin.pack('A', pkt.ip_bin_src)
			local status, length, _, layer3 = pcap:pcap_receive()
			while status and test ~= check(layer3) do
				status, length, _, layer3 = pcap:pcap_receive()
			end

			if status then
				local t, v = checkpkt(layer3, pkt)
				if t == "gotreply" then
					gotit = true
					break
				elseif t == "recap" then
				elseif t == "nextmtu" then
					if v == 0 then
						-- Router didn't send its
						-- next-hop MTU. Just drop
						-- a level.
						break
					end
					-- Lua's lack of a continue statement
					-- for loop control sucks, so dec m
					-- here as it's inc'd below.  Ugh.
					m = searchmtu(m, v) - 1
					mtuset = v
					break
				end
			else
				if r >= RETRIES then
					break
				end
				r = r + 1
			end
		end

		if gotit then
			break
		end

		m = m + 1
	end

	pcap:close()
	sock:ip_close()

	if not gotit then
		if nmap.debugging() > 0 then
			return "Error: Unable to determine PMTU (no replies)"
		end
		return
	end

	if MTUS[m] == mtuset then
		return "PMTU == " .. MTUS[m]
	elseif m == 1 then
		return "PMTU >= " .. MTUS[m]
	else
		return "" .. MTUS[m] .. " <= PMTU < " .. MTUS[m - 1]
	end
end

