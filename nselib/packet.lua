---
-- Facilities for manipulating raw packets.
--
-- @author Marek Majkowski <majek04+nse@gmail.com>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "packet" ,package.seeall)

local bit = require "bit"
local stdnse = require "stdnse"


----------------------------------------------------------------------------------------------------------------
--- Get an 8-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return An 8-bit integer.
function u8(b, i)
        return string.byte(b, i+1)
end
--- Get a 16-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 16-bit integer.
function u16(b, i)
        local b1,b2
        b1, b2 = string.byte(b, i+1), string.byte(b, i+2)
        --        2^8     2^0
        return b1*256 + b2
end
--- Get a 32-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 32-bit integer.
function u32(b,i)
        local b1,b2,b3,b4
        b1, b2 = string.byte(b, i+1), string.byte(b, i+2)
        b3, b4 = string.byte(b, i+3), string.byte(b, i+4)
        --        2^24          2^16       2^8     2^0
        return b1*16777216 + b2*65536 + b3*256 + b4
end

--- Set an 8-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
function set_u8(b, i, num)
	local s = string.char(bit.band(num, 0xff))
	return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+1)
end
--- Set a 16-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
function set_u16(b, i, num)
	local s = string.char(bit.band(bit.rshift(num, 8), 0xff)) .. string.char(bit.band(num, 0xff))
	return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+2)
end
--- Set a 32-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
function set_u32(b,i, num)
	local s = string.char(bit.band(bit.rshift(num,24), 0xff)) ..
		string.char(bit.band(bit.rshift(num,16), 0xff)) ..
		string.char(bit.band(bit.rshift(num,8), 0xff)) ..
		string.char(bit.band(num, 0xff))
	return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+4)
end


--- Calculate a standard Internet checksum.
-- @param b Data to checksum.
-- @return Checksum.
function in_cksum(b)
	local sum = 0
	local i

	-- Note we are using 0-based indexes here.
	i = 0
	while i < b:len() - 1 do
		sum = sum + u16(b, i)
		i = i + 2
	end
	if i < b:len() then
		sum = sum + u8(b, i) * 256
	end

	sum = bit.rshift(sum, 16) + bit.band(sum, 0xffff)
	sum = sum + bit.rshift(sum, 16)
	sum = bit.bnot(sum)
	sum = bit.band(sum, 0xffff) -- trunctate to 16 bits
	return sum
end

-- ip protocol field
IPPROTO_IP   = 0               	--  Dummy protocol for TCP
IPPROTO_ICMP = 1             	--  Internet Control Message Protocol
IPPROTO_IGMP = 2             	--  Internet Group Management Protocol
IPPROTO_IPIP = 4             	--  IPIP tunnels (older KA9Q tunnels use 94)
IPPROTO_TCP  = 6              	--  Transmission Control Protocol
IPPROTO_EGP  = 8              	--  Exterior Gateway Protocol
IPPROTO_PUP  = 12             	--  PUP protocol
IPPROTO_UDP  = 17             	--  User Datagram Protocol
IPPROTO_IDP  = 22             	--  XNS IDP protocol
IPPROTO_DCCP = 33            	--  Datagram Congestion Control Protocol
IPPROTO_RSVP = 46            	--  RSVP protocol
IPPROTO_GRE  = 47             	--  Cisco GRE tunnels (rfc 1701,1702)
IPPROTO_IPV6 = 41             	--  IPv6-in-IPv4 tunnelling

IPPROTO_ESP  = 50            	--  Encapsulation Security Payload protocol
IPPROTO_AH   = 51             	--  Authentication Header protocol
IPPROTO_BEETPH  = 94         	--  IP option pseudo header for BEET
IPPROTO_PIM     = 103         	--  Protocol Independent Multicast

IPPROTO_COMP    = 108        	--  Compression Header protocol
IPPROTO_SCTP    = 132         	--  Stream Control Transport Protocol
IPPROTO_UDPLITE = 136        	--  UDP-Lite (RFC 3828)


----------------------------------------------------------------------------------------------------------------
-- Packet is a class
Packet = {}

--- Create a new Packet object.
-- @param packet Binary string with packet data.
-- @param packet_len Packet length. It could be more than
-- <code>#packet</code>.
-- @param force_continue whether an error in parsing headers should be fatal or
-- not. This is especially useful when parsing ICMP packets, where a small ICMP
-- payload could be a TCP header. The problem is that parsing this payload
-- normally would fail because the TCP header is too small.
-- @return A new Packet.
function Packet:new(packet, packet_len, force_continue)
	local o = setmetatable({}, {__index = Packet})
	o.buf		= packet
	o.packet_len	= packet_len
	if not o:ip_parse(force_continue) then
		return nil
	end
	if o.ip_p == IPPROTO_TCP then
		if not o:tcp_parse(force_continue) then
			stdnse.print_debug("Error while parsing TCP packet\n")
		end
	elseif o.ip_p == IPPROTO_UDP then
		if not o:udp_parse(force_continue) then
			stdnse.print_debug("Error while parsing UDP packet\n")
		end
	elseif o.ip_p == IPPROTO_ICMP then
		if not o:icmp_parse(force_continue) then
			stdnse.print_debug("Error while parsing ICMP packet\n")
		end
	end
	return o
end

-- Helpers


--- Convert a dotted-quad IP address string (like <code>"1.2.3.4"</code>) to a
-- raw string four bytes long.
-- @param str IP address string.
-- @return Four-byte string.
function iptobin(str)
	local ret = ""
        for c in string.gmatch(str, "[0-9]+") do
                ret = ret .. string.char(c+0) -- automatic conversion to int
        end
	return ret
end
--- Convert a four-byte raw string to a dotted-quad IP address string.
-- @param raw_ip_addr Four-byte string.
-- @return IP address string.
function toip(raw_ip_addr)
	if not raw_ip_addr then
		return "?.?.?.?"
	end
	return string.format("%i.%i.%i.%i", string.byte(raw_ip_addr,1,4))
end
--- Get an 8-bit integer at a 0-based byte offset in the packet.
-- @param index Offset.
-- @return An 8-bit integer.
function Packet:u8(index)
        return u8(self.buf, index)
end
--- Get a 16-bit integer at a 0-based byte offset in the packet.
-- @param index Offset.
-- @return A 16-bit integer.
function Packet:u16(index)
        return u16(self.buf, index)
end
--- Get a 32-bit integer at a 0-based byte offset in the packet.
-- @param index Offset.
-- @return An 32-bit integer.
function Packet:u32(index)
        return u32(self.buf, index)
end
--- Return part of the packet contents as a byte string.
-- @param index The beginning of the part of the packet to extract.
-- @param length The length of the part of the packet to extract.
-- @return A string.
function Packet:raw(index, length)
        return string.char(string.byte(self.buf, index+1, index+1+length-1))
end

--- Set an 8-bit integer at a 0-based byte offset in the packet.
-- (big-endian).
-- @param index Offset.
-- @param num Integer to store.
function Packet:set_u8(index, num)
        self.buf = set_u8(self.buf, index, num)
        return self.buf
end
--- Set a 16-bit integer at a 0-based byte offset in the packet.
-- (big-endian).
-- @param index Offset.
-- @param num Integer to store.
function Packet:set_u16(index, num)
        self.buf = set_u16(self.buf, index, num)
        return self.buf
end
--- Set a 32-bit integer at a 0-based byte offset in the packet.
-- (big-endian).
-- @param index Offset.
-- @param num Integer to store.
function Packet:set_u32(index, num)
        self.buf = set_u32(self.buf, index, num)
        return self.buf
end

--- Parse an IP packet header.
-- @param force_continue Ignored.
-- @return Whether the parsing succeeded.
function Packet:ip_parse(force_continue)
	self.ip_offset		= 0
	if    #self.buf < 20 then 	-- too short
		return false
	end
	self.ip_v		= bit.rshift(bit.band(self:u8(self.ip_offset + 0), 0xF0), 4)
	self.ip_hl		=            bit.band(self:u8(self.ip_offset + 0), 0x0F)		-- header_length or data_offset
	if    self.ip_v ~= 4 then 	-- not ip
		return false
	end
	self.ip = true
	self.ip_tos		= self:u8(self.ip_offset + 1)
	self.ip_len		= self:u16(self.ip_offset + 2)
	self.ip_id		= self:u16(self.ip_offset + 4)
	self.ip_off		= self:u16(self.ip_offset + 6)
	self.ip_rf		= bit.band(self.ip_off, 0x8000)~=0		-- true/false
	self.ip_df		= bit.band(self.ip_off, 0x4000)~=0
	self.ip_mf		= bit.band(self.ip_off, 0x2000)~=0
	self.ip_off		= bit.band(self.ip_off, 0x1FFF)		-- fragment offset
	self.ip_ttl		= self:u8(self.ip_offset + 8)
	self.ip_p		= self:u8(self.ip_offset + 9)
	self.ip_sum		= self:u16(self.ip_offset + 10)
	self.ip_bin_src		= self:raw(self.ip_offset + 12,4)	-- raw 4-bytes string
	self.ip_bin_dst		= self:raw(self.ip_offset + 16,4)
	self.ip_src		= toip(self.ip_bin_src)		-- formatted string
	self.ip_dst		= toip(self.ip_bin_dst)
	self.ip_opt_offset	= self.ip_offset + 20
	self.ip_options		= self:parse_options(self.ip_opt_offset, ((self.ip_hl*4)-20))
	self.ip_data_offset	= self.ip_offset + self.ip_hl*4
	return true
end
--- Set the header length field.
function Packet:ip_set_hl(len)
	self:set_u8(self.ip_offset + 0, bit.bor(bit.lshift(self.ip_v, 4), bit.band(len, 0x0F)))
	self.ip_v		= bit.rshift(bit.band(self:u8(self.ip_offset + 0), 0xF0), 4)
	self.ip_hl		=            bit.band(self:u8(self.ip_offset + 0), 0x0F)		-- header_length or data_offset
end
--- Set the packet length field.
-- @param len Packet length.
function Packet:ip_set_len(len)
	self:set_u16(self.ip_offset + 2, len)
	self.ip_len = len
end
--- Set the TTL.
-- @param ttl TTL.
function Packet:ip_set_ttl(ttl)
	self:set_u8(self.ip_offset + 8, ttl)
	self.ip_ttl = ttl
end
--- Set the checksum.
-- @param checksum Checksum.
function Packet:ip_set_checksum(checksum)
	self:set_u16(self.ip_offset + 10, checksum)
	self.ip_sum = checksum
end
--- Count checksum for packet and save it.
function Packet:ip_count_checksum()
	self:ip_set_checksum(0)
	local csum = in_cksum( self.buf:sub(0, self.ip_offset + self.ip_hl*4)  )
	self:ip_set_checksum(csum)
end
--- Set the source IP address.
-- @param binip The source IP address as a byte string.
function Packet:ip_set_bin_src(binip)
	local nrip = u32(binip, 0)
	self:set_u32(self.ip_offset + 12, nrip)
	self.ip_bin_src		= self:raw(self.ip_offset + 12,4)	-- raw 4-bytes string
end
--- Set the destination IP address.
-- @param binip The destination IP address as a byte string.
function Packet:ip_set_bin_dst(binip)
	local nrip = u32(binip, 0)
	self:set_u32(self.ip_offset + 16, nrip)
	self.ip_bin_dst		= self:raw(self.ip_offset + 16,4)
end
--- Set the IP options field (and move the data, count new length,
-- etc.).
-- @param ipoptions IP options.
function Packet:ip_set_options(ipoptions)
	-- packet = <ip header> + ipoptions + <payload>
	local buf = self.buf:sub(0+1,self.ip_offset + 20) .. ipoptions .. self.buf:sub(self.ip_data_offset+1)
	self.buf = buf
	-- set ip_len
	self:ip_set_len(self.buf:len())
	-- set ip_hl
	self:ip_set_hl(5 + ipoptions:len()/4)
	-- set data offset correctly
	self.ip_options		= self:parse_options(self.ip_opt_offset, ((self.ip_hl*4)-20))
	self.ip_data_offset	= self.ip_offset + self.ip_hl*4
	if self.tcp then
		self.tcp_offset		= self.ip_data_offset
	elseif self.icmp then
		self.icmp_offset	= self.ip_data_offset
	end
end

--- Get a short string representation of the IP header.
-- @return A string representation of the IP header.
function Packet:ip_tostring()
	return string.format(
		"IP %s -> %s",
		self.ip_src,
		self.ip_dst)
end

--- Parse IP/TCP options into a table.
-- @param offset Offset at which options start.
-- @param length Length of options.
-- @return Table of options.
function Packet:parse_options(offset, length)
	local options = {}
	local op = 1
	local opt_ptr = 0
	while opt_ptr < length do
		local t, l, d
		options[op] = {}

		t = self:u8(offset + opt_ptr)
		options[op].type = t
		if t==0 or t==1 then
			l = 1
			d = nil
		else
			l = self:u8(offset + opt_ptr + 1)
			if l > 2 then
			d = self:raw(offset + opt_ptr + 2, l-2)
			end
		end
		options[op].len  = l
		options[op].data = d
		opt_ptr = opt_ptr + l
		op = op + 1
	end
	return options
end

--- Get a short string representation of the packet.
-- @return A string representation of the packet.
function Packet:tostring()
	if self.tcp then
		return self:tcp_tostring()
	elseif self.udp then
		return self:udp_tostring()
	elseif self.icmp then
		return self:icmp_tostring()
	elseif self.ip then
		return self:ip_tostring()
	end
	return "<no tostring!>"
end

----------------------------------------------------------------------------------------------------------------
--- Parse an ICMP packet header.
-- @param force_continue Ignored.
-- @return Whether the parsing succeeded.
function Packet:icmp_parse(force_continue)
	self.icmp_offset	= self.ip_data_offset
	if #self.buf < self.icmp_offset + 8 then -- let's say 8 bytes minimum
		return false
	end
	self.icmp = true
	self.icmp_type		= self:u8(self.icmp_offset + 0)
	self.icmp_code		= self:u8(self.icmp_offset + 1)
	self.icmp_sum		= self:u16(self.icmp_offset + 2)

	if self.icmp_type == 3 or self.icmp_type == 4 or self.icmp_type == 11 or self.icmp_type == 12 then
		self.icmp_payload = true
		self.icmp_r0	  = self:u32(self.icmp_offset + 4)
		self.icmp_payload_offset = self.icmp_offset + 8
		if #self.buf < self.icmp_payload_offset + 24 then
			return false
		end
		self.icmp_payload = Packet:new(self.buf:sub(self.icmp_payload_offset+1), self.packet_len - self.icmp_payload_offset, true)
	end
	return true
end
--- Get a short string representation of the ICMP header.
-- @return A string representation of the ICMP header.
function Packet:icmp_tostring()
	return self:ip_tostring() .. " ICMP(" .. self.icmp_payload:tostring() .. ")"
end

----------------------------------------------------------------------------------------------------------------
-- Parse a TCP packet header.
-- @param force_continue Whether a short packet causes parsing to fail.
-- @return Whether the parsing succeeded.
function Packet:tcp_parse(force_continue)
	self.tcp = true
	self.tcp_offset		= self.ip_data_offset
	if #self.buf < self.tcp_offset + 4 then
		return false
	end
	self.tcp_sport		= self:u16(self.tcp_offset + 0)
	self.tcp_dport		= self:u16(self.tcp_offset + 2)
	if #self.buf < self.tcp_offset + 20 then
		if force_continue then
			return true
		else
			return false
		end
	end
	self.tcp_seq		= self:u32(self.tcp_offset + 4)
	self.tcp_ack		= self:u32(self.tcp_offset + 8)
	self.tcp_hl		= bit.rshift(bit.band(self:u8(self.tcp_offset+12), 0xF0), 4)	-- header_length or data_offset
	self.tcp_x2		=            bit.band(self:u8(self.tcp_offset+12), 0x0F)
	self.tcp_flags		= self:u8(self.tcp_offset + 13)
	self.tcp_th_fin		= bit.band(self.tcp_flags, 0x01)~=0		-- true/false
	self.tcp_th_syn		= bit.band(self.tcp_flags, 0x02)~=0
	self.tcp_th_rst		= bit.band(self.tcp_flags, 0x04)~=0
	self.tcp_th_push	= bit.band(self.tcp_flags, 0x08)~=0
	self.tcp_th_ack		= bit.band(self.tcp_flags, 0x10)~=0
	self.tcp_th_urg		= bit.band(self.tcp_flags, 0x20)~=0
	self.tcp_th_ece		= bit.band(self.tcp_flags, 0x40)~=0
	self.tcp_th_cwr		= bit.band(self.tcp_flags, 0x80)~=0
	self.tcp_win		= self:u16(self.tcp_offset + 14)
	self.tcp_sum		= self:u16(self.tcp_offset + 16)
	self.tcp_urp		= self:u16(self.tcp_offset + 18)
	self.tcp_opt_offset	= self.tcp_offset + 20
	self.tcp_options	= self:parse_options(self.tcp_opt_offset, ((self.tcp_hl*4)-20))
	self.tcp_data_offset	= self.tcp_offset + self.tcp_hl*4
	self.tcp_data_length	= self.ip_len - self.tcp_offset - self.tcp_hl*4
        self:tcp_parse_options()
	return true
end

--- Get a short string representation of the TCP packet.
-- @return A string representation of the TCP header.
function Packet:tcp_tostring()
	return string.format(
		"TCP %s:%i -> %s:%i",
		self.ip_src, self.tcp_sport,
		self.ip_dst, self.tcp_dport
		)
end

--- Parse options for TCP header.
function Packet:tcp_parse_options()
        local eoo = false
	for _,opt in ipairs(self.tcp_options) do
                if eoo then
                        self.tcp_opt_after_eol = true
                end

		if      opt.type == 0 then    -- end of options
                        eoo = true
                elseif 	opt.type == 2 then    -- MSS
                        self.tcp_opt_mss = u16(opt.data, 0)
                        self.tcp_opt_mtu = self.tcp_opt_mss + 40
		elseif	opt.type == 3 then     -- widow scaling
                        self.tcp_opt_ws  = u8(opt.data, 0)
		elseif	opt.type == 8 then     -- timestamp
                        self.tcp_opt_t1 = u32(opt.data, 0)
                        self.tcp_opt_t2 = u32(opt.data, 4)
		end
	end
end

--- Set the TCP source port.
-- @param port Source port.
function Packet:tcp_set_sport(port)
	self:set_u16(self.tcp_offset + 0, port)
	self.tcp_sport = port
end
--- Set the TCP destination port.
-- @param port Destination port.
function Packet:tcp_set_dport(port)
	self:set_u16(self.tcp_offset + 2, port)
	self.tcp_dport = port
end
--- Set the TCP sequence field.
-- @param new_seq Sequence.
function Packet:tcp_set_seq(new_seq)
	self:set_u32(self.tcp_offset + 4, new_seq)
	self.tcp_seq = new_seq
end
--- Set the TCP flags field (like SYN, ACK, RST).
-- @param new_flags Flags, represented as an 8-bit number.
function Packet:tcp_set_flags(new_flags)
	self:set_u8(self.tcp_offset + 13, new_flags)
	self.tcp_flags = new_flags
end
--- Set the urgent pointer field.
-- @param urg_ptr Urgent pointer.
function Packet:tcp_set_urp(urg_ptr)
	self:set_u16(self.tcp_offset + 18, urg_ptr)
	self.tcp_urp = urg_ptr
end
--- Set the TCP checksum field.
-- @param checksum Checksum.
function Packet:tcp_set_checksum(checksum)
	self:set_u16(self.tcp_offset + 16, checksum)
	self.tcp_sum = checksum
end
--- Count and save the TCP checksum field.
function Packet:tcp_count_checksum()
	self:tcp_set_checksum(0)
	local proto	= self.ip_p
	local length	= self.buf:len() - self.tcp_offset
	local b = self.ip_bin_src ..
		self.ip_bin_dst ..
		string.char(0) ..
		string.char(proto) ..
		set_u16("..", 0, length) ..
		self.buf:sub(self.tcp_offset+1)

	self:tcp_set_checksum(in_cksum(b))
end

--- Map an MTU to a link type string. Stolen from p0f.
-- @return A string describing the link type.
function Packet:tcp_lookup_link()
        local mtu_def = {
            {["mtu"]=256,   ["txt"]= "radio modem"},
            {["mtu"]=386,   ["txt"]= "ethernut"},
            {["mtu"]=552,   ["txt"]= "SLIP line / encap ppp"},
            {["mtu"]=576,   ["txt"]= "sometimes modem"},
            {["mtu"]=1280,  ["txt"]= "gif tunnel"},
            {["mtu"]=1300,  ["txt"]= "PIX, SMC, sometimes wireless"},
            {["mtu"]=1362,  ["txt"]= "sometimes DSL (1)"},
            {["mtu"]=1372,  ["txt"]= "cable modem"},
            {["mtu"]=1400,  ["txt"]= "(Google/AOL)"},
            {["mtu"]=1415,  ["txt"]= "sometimes wireless"},
            {["mtu"]=1420,  ["txt"]= "GPRS, T1, FreeS/WAN"},
            {["mtu"]=1423,  ["txt"]= "sometimes cable"},
            {["mtu"]=1440,  ["txt"]= "sometimes DSL (2)"},
            {["mtu"]=1442,  ["txt"]= "IPIP tunnel"},
            {["mtu"]=1450,  ["txt"]= "vtun"},
            {["mtu"]=1452,  ["txt"]= "sometimes DSL (3)"},
            {["mtu"]=1454,  ["txt"]= "sometimes DSL (4)"},
            {["mtu"]=1456,  ["txt"]= "ISDN ppp"},
            {["mtu"]=1458,  ["txt"]= "BT DSL (?)"},
            {["mtu"]=1462,  ["txt"]= "sometimes DSL (5)"},
            {["mtu"]=1470,  ["txt"]= "(Google 2)"},
            {["mtu"]=1476,  ["txt"]= "IPSec/GRE"},
            {["mtu"]=1480,  ["txt"]= "IPv6/IPIP"},
            {["mtu"]=1492,  ["txt"]= "pppoe (DSL)"},
            {["mtu"]=1496,  ["txt"]= "vLAN"},
            {["mtu"]=1500,  ["txt"]= "ethernet/modem"},
            {["mtu"]=1656,  ["txt"]= "Ericsson HIS"},
            {["mtu"]=2024,  ["txt"]= "wireless/IrDA"},
            {["mtu"]=2048,  ["txt"]= "Cyclom X.25 WAN"},
            {["mtu"]=2250,  ["txt"]= "AiroNet wireless"},
            {["mtu"]=3924,  ["txt"]= "loopback"},
            {["mtu"]=4056,  ["txt"]= "token ring (1)"},
            {["mtu"]=4096,  ["txt"]= "Sangoma X.25 WAN"},
            {["mtu"]=4352,  ["txt"]= "FDDI"},
            {["mtu"]=4500,  ["txt"]= "token ring (2)"},
            {["mtu"]=9180,  ["txt"]= "FORE ATM"},
            {["mtu"]=16384, ["txt"]= "sometimes loopback (1)"},
            {["mtu"]=16436, ["txt"]= "sometimes loopback (2)"},
            {["mtu"]=18000, ["txt"]= "token ring x4"},
            }
        if not self.tcp_opt_mss or self.tcp_opt_mss==0 then
                return "unspecified"
        end
        for _,x in ipairs(mtu_def) do
                local mtu = x["mtu"]
                local txt = x["txt"]
                if self.tcp_opt_mtu == mtu then
                        return txt
                end
                if self.tcp_opt_mtu < mtu then
                        return string.format("unknown-%i", self.tcp_opt_mtu)
                end
        end
        return string.format("unknown-%i", self.tcp_opt_mtu)
end

----------------------------------------------------------------------------------------------------------------
-- Parse a UDP packet header.
-- @param force_continue Whether a short packet causes parsing to fail.
-- @return Whether the parsing succeeded.
function Packet:udp_parse(force_continue)
	self.udp = true
	self.udp_offset		= self.ip_data_offset
	if #self.buf < self.udp_offset + 4 then
		return false
	end
	self.udp_sport		= self:u16(self.udp_offset + 0)
	self.udp_dport		= self:u16(self.udp_offset + 2)
	if #self.buf < self.udp_offset + 8 then
		if force_continue then
			return true
		else
			return false
		end
	end
	self.udp_len		= self:u16(self.udp_offset + 4)
	self.udp_sum		= self:u16(self.udp_offset + 6)
	
	return true
end

--- Get a short string representation of the UDP packet.
-- @return A string representation of the UDP header.
function Packet:udp_tostring()
	return string.format(
		"UDP %s:%i -> %s:%i",
		self.ip_src, self.udp_sport,
		self.ip_dst, self.udp_dport
	)
end

---
-- Set the UDP source port.
-- @param port Source port.
function Packet:udp_set_sport(port)
	self:set_u16(self.udp_offset + 0, port)
	self.udp_sport = port
end
---
-- Set the UDP destination port.
-- @param port Destination port.
function Packet:udp_set_dport(port)
	self:set_u16(self.udp_offset + 2, port)
	self.udp_dport = port
end
---
-- Set the UDP payload length.
-- @param len UDP payload length.
function Packet:udp_set_length(len)
	self:set_u16(self.udp_offset + 4, len)
	self.udp_len = len
end
---
-- Set the UDP checksum field.
-- @param checksum Checksum.
function Packet:udp_set_checksum(checksum)
	self:set_u16(self.udp_offset + 6, checksum)
	self.udp_sum = checksum
end
---
-- Count and save the UDP checksum field.
function Packet:udp_count_checksum()
	self:udp_set_checksum(0)
	local proto	= self.ip_p
	local length	= self.buf:len() - self.udp_offset
	local b = self.ip_bin_src ..
		self.ip_bin_dst ..
		string.char(0) ..
		string.char(proto) ..
		set_u16("..", 0, length) ..
		self.buf:sub(self.udp_offset+1)

	self:udp_set_checksum(in_cksum(b))
end

