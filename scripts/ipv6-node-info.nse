local bin = require "bin"
local bit = require "bit"
local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

description = [[
Obtains hostnames, IPv4 and IPv6 addresses through IPv6 Node Information Queries.

IPv6 Node Information Queries are defined in RFC 4620. There are three
useful types of queries:
* qtype=2: Node Name
* qtype=3: Node Addresses
* qtype=4: IPv4 Addresses

Some operating systems (Mac OS X and OpenBSD) return hostnames in
response to qtype=4, IPv4 Addresses. In this case, the hostnames are still
shown in the "IPv4 addresses" output row, but are prefixed by "(actually
hostnames)".
]]

---
-- @usage nmap -6 <target>
--
-- @output
-- | ipv6-node-info:
-- |   Hostnames: mac-mini.local
-- |   IPv6 addresses: fe80::a8bb:ccff:fedd:eeff, 2001:db8:1234:1234::3
-- |_  IPv4 addresses: (actually hostnames) mac-mini.local

categories = {"default", "discovery", "safe"}

author = "David Fifield"


local ICMPv6_NODEINFOQUERY = 139
local   ICMPv6_NODEINFOQUERY_IPv6ADDR = 0
local   ICMPv6_NODEINFOQUERY_NAME = 1
local   ICMPv6_NODEINFOQUERY_IPv4ADDR = 1
local ICMPv6_NODEINFORESP = 140
local   ICMPv6_NODEINFORESP_SUCCESS = 0
local   ICMPv6_NODEINFORESP_REFUSED = 1
local   ICMPv6_NODEINFORESP_UNKNOWN = 2

local QTYPE_NOOP = 0
local QTYPE_NODENAME = 2
local QTYPE_NODEADDRESSES = 3
local QTYPE_NODEIPV4ADDRESSES = 4

local QTYPE_STRINGS = {
	[QTYPE_NOOP] = "NOOP",
	[QTYPE_NODENAME] = "Hostnames",
	[QTYPE_NODEADDRESSES] = "IPv6 addresses",
	[QTYPE_NODEIPV4ADDRESSES] = "IPv4 addresses",
}

local function build_ni_query(src, dst, qtype)
	local payload, p, flags
	local nonce

	nonce = openssl.rand_pseudo_bytes(8)
	if qtype == QTYPE_NODENAME then
		flags = 0x0000
	elseif qtype == QTYPE_NODEADDRESSES then
		-- Set all the flags GSLCA (see RFC 4620, Figure 3).
		flags = 0x003E
	elseif qtype == QTYPE_NODEIPV4ADDRESSES then
		-- Set the A flag (see RFC 4620, Figure 4).
		flags = 0x0002
	else
		error("Unknown qtype " .. qtype)
	end
	payload = bin.pack(">SSAA", qtype, flags, nonce, dst)
	p = packet.Packet:new()
	p:build_icmpv6_header(ICMPv6_NODEINFOQUERY, ICMPv6_NODEINFOQUERY_IPv6ADDR, payload, src, dst)
	p:build_ipv6_packet(src, dst, packet.IPPROTO_ICMPV6)

	return p.buf
end

function hostrule(host)
	return nmap.is_privileged() and #host.bin_ip == 16 and host.interface
end

local function open_sniffer(host)
	local bpf
	local s

	s = nmap.new_socket()
	bpf = string.format("ip6 and src host %s", host.ip)
	s:pcap_open(host.interface, 1500, false, bpf)

	return s
end

local function send_queries(host)
	local dnet

	dnet = nmap.new_dnet()
	dnet:ip_open()
	local p = build_ni_query(host.bin_ip_src, host.bin_ip, QTYPE_NODEADDRESSES)
	dnet:ip_send(p, host)
	p = build_ni_query(host.bin_ip_src, host.bin_ip, QTYPE_NODENAME)
	dnet:ip_send(p, host)
	p = build_ni_query(host.bin_ip_src, host.bin_ip, QTYPE_NODEIPV4ADDRESSES)
	dnet:ip_send(p, host)
	dnet:ip_close()
end

local function empty(t)
	return not next(t)
end

-- Try to decode a Node Name reply data field. If successful, returns true and
-- a list of DNS names. In case of a parsing error, returns false and the
-- partial list of names that were parsed prior to the error.
local function try_decode_nodenames(data)
	local ttl
	local names = {}
	local pos = nil

	pos, ttl = bin.unpack(">I", data, pos)
	if not ttl then
		return false, names
	end
	while pos <= #data do
		local name

		pos, name = dns.decStr(data, pos)
		if not name then
			return false, names
		end
		-- Ignore empty names, such as those at the end.
		if name ~= "" then
			names[#names + 1] = name
		end
	end

	return true, names
end

local function stringify_noop(flags, data)
	return "replied"
end

-- RFC 4620, section 6.3.
local function stringify_nodename(flags, data)
	local status, names
	local text

	status, names = try_decode_nodenames(data)
	if empty(names) then
		return
	end
	text = stdnse.strjoin(", ", names)
	if not status then
		text = text .. " (parsing error)"
	end

	return text
end

-- RFC 4620, section 6.3.
local function stringify_nodeaddresses(flags, data)
	local ttl, binaddr
	local text
	local addrs = {}
	local pos = nil

	while true do
		pos, ttl, binaddr = bin.unpack(">IA16", data, pos)
		if not ttl then
			break
		end
		addrs[#addrs + 1] = packet.toipv6(binaddr)
	end
	if empty(addrs) then
		return
	end

	text = stdnse.strjoin(", ", addrs)
	if bit.band(flags, 0x01) ~= 0 then
		text = text .. " (more omitted for space reasons)"
	end

	return text
end

-- RFC 4620, section 6.4.
-- But Mac OS X puts DNS names in here instead of IPv4 addresses, but it
-- doesn't include the two empty labels at the end as it does with a Node Name
-- response. For example, here is a Node Name reply:
-- 00 00 00 00 0e 6d 61 63  2d 6d 69 6e 69 2e 6c 6f    .....mac -mini.lo
-- 63 61 6c 00 00                                      cal..
-- And here is a Node Addresses reply:
-- 00 00 00 00 0e 6d 61 63  2d 6d 69 6e 69 2e 6c 6f    .....mac -mini.lo
-- 63 61 6c                                            cal
local function stringify_nodeipv4addresses(flags, data)
	local status, names
	local ttl, binaddr
	local text
	local addrs = {}
	local pos = nil

	-- Check for DNS names.
	status, names = try_decode_nodenames(data .. "\0\0")
	if status then
		return "(actually hostnames) " .. stdnse.strjoin(", ", names)
	end

	-- Okay, looks like it's really IP addresses.
	while true do
		pos, ttl, binaddr = bin.unpack(">IA4", data, pos)
		if not ttl then
			break
		end
		addrs[#addrs + 1] = packet.toip(binaddr)
	end
	if empty(addrs) then
		return
	end

	text = stdnse.strjoin(", ", addrs)
	if bit.band(flags, 0x01) ~= 0 then
		text = text .. " (more omitted for space reasons)"
	end

	return text
end

local STRINGIFY = {
	[QTYPE_NOOP] = stringify_noop,
	[QTYPE_NODENAME] = stringify_nodename,
	[QTYPE_NODEADDRESSES] = stringify_nodeaddresses,
	[QTYPE_NODEIPV4ADDRESSES] = stringify_nodeipv4addresses,
}

local function handle_received_packet(buf)
	local p, qtype, flags, data
	local text

	p = packet.Packet:new(buf)
	if p.icmpv6_type ~= ICMPv6_NODEINFORESP then
		return
	end
	qtype = packet.u16(p.buf, p.icmpv6_offset + 4)
	flags = packet.u16(p.buf, p.icmpv6_offset + 6)
	data = string.sub(p.buf, p.icmpv6_offset + 16 + 1)

	if not STRINGIFY[qtype] then
		-- This is a not a qtype we sent or know about.
		stdnse.print_debug(1, "Got NI reply with unknown qtype %d from %s", qtype, p.ip6_src)
		return
	end

	if p.icmpv6_code == ICMPv6_NODEINFORESP_SUCCESS then
		text = STRINGIFY[qtype](flags, data)
	elseif p.icmpv6_code == ICMPv6_NODEINFORESP_REFUSED then
		text = "refused"
	elseif p.icmpv6_code == ICMPv6_NODEINFORESP_UNKNOWN then
		text = string.format("target said: qtype %d is unknown", qtype)
	else
		text = string.format("unknown ICMPv6 code %d for qtype %d", p.icmpv6_code, qtype)
	end

	return qtype, text
end

local function format_results(results)
	local QTYPE_ORDER = {
		QTYPE_NOOP,
		QTYPE_NODENAME,
		QTYPE_NODEADDRESSES,
		QTYPE_NODEIPV4ADDRESSES,
	}
	local output

	output = {}
	for _, qtype in ipairs(QTYPE_ORDER) do
		if results[qtype] then
			output[#output + 1] = QTYPE_STRINGS[qtype] .. ": " .. results[qtype]
		end
	end

	return stdnse.format_output(true, output)
end

function action(host)
	local s
	local timeout, end_time, now
	local pending, results

	timeout = host.times.timeout * 10

	s = open_sniffer(host)

	send_queries(host)

	pending = {
		[QTYPE_NODENAME] = true,
		[QTYPE_NODEADDRESSES] = true,
		[QTYPE_NODEIPV4ADDRESSES] = true,
	}
	results = {}

	now = nmap.clock_ms()
	end_time = now + timeout
	repeat
		local _, status, buf

		s:set_timeout((end_time - now) * 1000)

		status, _, _, buf = s:pcap_receive()
		if status then
			local qtype, text = handle_received_packet(buf)
			if qtype then
				results[qtype] = text
				pending[qtype] = nil
			end
		end

		now = nmap.clock_ms()
	until empty(pending) or now > end_time

	s:pcap_close()

	return format_results(results)
end
