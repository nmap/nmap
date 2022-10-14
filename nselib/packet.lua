---
-- Facilities for manipulating raw packets.
--
-- @author Marek Majkowski <majek04+nse@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local unittest = require "unittest"
_ENV = stdnse.module("packet", stdnse.seeall)


----------------------------------------------------------------------------------------------------------------
--- Get an 8-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return An 8-bit integer.
local function u8(b, i)
  return b:byte(i+1)
end
--- Get a 16-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 16-bit integer.
local function u16(b, i)
  return (">I2"):unpack(b, i+1)
end
--- Get a 32-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 32-bit integer.
local function u32(b,i)
  return (">I4"):unpack(b, i+1)
end

--- Set an 8-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
local function set_u8(b, i, num)
  local s = string.char(num & 0xff)
  return b:sub(0+1, i+1-1) .. s .. b:sub(i+1+1)
end
--- Set a 16-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
local function set_u16(b, i, num)
  return b:sub(0+1, i+1-1) .. (">I2"):pack(num) .. b:sub(i+1+2)
end
--- Set a 32-bit integer at a 0-based byte offset in a byte string
-- (big-endian).
-- @param b A byte string.
-- @param i Offset.
-- @param num Integer to store.
local function set_u32(b,i, num)
  return b:sub(0+1, i+1-1) .. (">I4"):pack(num) .. b:sub(i+1+4)
end

--- Calculate a standard Internet checksum.
-- @param b Data to checksum.
-- @return Checksum.
function in_cksum(b)
  local sum = 0

  -- Pad to even length, then sum up
  string.gsub(b .. ("\0"):rep(#b % 2), "..", function(twobytes)
      sum = sum + (">I2"):unpack(twobytes)
    end)

  local shifted = sum >> 16
  while shifted > 0 do
    sum = (sum & 0xffff) + shifted
    shifted = sum >> 16
  end

  sum = ~sum
  sum = (sum & 0xffff) -- truncate to 16 bits
  return sum
end

-- ip protocol field
IPPROTO_IP   = 0      --  Dummy protocol for TCP
IPPROTO_HOPOPTS = 0   --  IPv6 hop-by-hop options
IPPROTO_ICMP = 1      --  Internet Control Message Protocol
IPPROTO_IGMP = 2      --  Internet Group Management Protocol
IPPROTO_IPIP = 4      --  IPIP tunnels (older KA9Q tunnels use 94)
IPPROTO_TCP  = 6      --  Transmission Control Protocol
IPPROTO_EGP  = 8      --  Exterior Gateway Protocol
IPPROTO_PUP  = 12     --  PUP protocol
IPPROTO_UDP  = 17     --  User Datagram Protocol
IPPROTO_IDP  = 22     --  XNS IDP protocol
IPPROTO_DCCP = 33     --  Datagram Congestion Control Protocol
IPPROTO_RSVP = 46     --  RSVP protocol
IPPROTO_GRE  = 47     --  Cisco GRE tunnels (rfc 1701,1702)
IPPROTO_IPV6 = 41     --  IPv6-in-IPv4 tunnelling

IPPROTO_ROUTING = 43  --  IPv6 routing header
IPPROTO_FRAGMENT= 44  --  IPv6 fragmentation header
IPPROTO_ESP     = 50  --  Encapsulation Security Payload protocol
IPPROTO_AH      = 51  --  Authentication Header protocol
IPPROTO_ICMPV6  = 58  --  ICMP for IPv6
IPPROTO_DSTOPTS = 60  --  IPv6 destination options
IPPROTO_BEETPH  = 94  --  IP option pseudo header for BEET
IPPROTO_PIM     = 103 --  Protocol Independent Multicast

IPPROTO_COMP    = 108 --  Compression Header protocol
IPPROTO_SCTP    = 132 --  Stream Control Transport Protocol
IPPROTO_UDPLITE = 136 --  UDP-Lite (RFC 3828)


ICMP_ECHO_REQUEST   = 8
ICMP_ECHO_REPLY     = 0

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
MLD_LISTENER_QUERY = 130
MLD_LISTENER_REPORT = 131
MLD_LISTENER_REDUCTION = 132
ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136
ND_REDIRECT = 137
MLDV2_LISTENER_REPORT = 143

ND_OPT_SOURCE_LINKADDR = 1
ND_OPT_TARGET_LINKADDR = 2
ND_OPT_PREFIX_INFORMATION = 3
ND_OPT_REDIRECTED_HEADER = 4
ND_OPT_MTU = 5
ND_OPT_RTR_ADV_INTERVAL = 7
ND_OPT_HOME_AGENT_INFO = 8

ETHER_TYPE_IPV4 = "\x08\x00"
ETHER_TYPE_IPV6 = "\x86\xdd"

----------------------------------------------------------------------------------------------------------------
-- Frame is a class
Frame = {}

function Frame:new(frame, force_continue)
  local packet = nil
  local packet_len = 0
  if frame and #frame > 14 then
    packet = string.sub(frame, 15, -1)
    packet_len = #frame - 14
  end
  local o = Packet:new(packet, packet_len, force_continue)

  o.build_ether_frame = self.build_ether_frame
  o.ether_parse = self.ether_parse
  o.frame_buf = frame
  o:ether_parse()
  return o
end
--- Build an Ethernet frame.
-- @param mac_dst six-byte string of the destination MAC address.
-- @param mac_src six-byte string of the source MAC address.
-- @param ether_type two-byte string of the type.
-- @param packet string of the payload.
-- @return frame string of the Ether frame.
function Frame:build_ether_frame(mac_dst, mac_src, ether_type, packet)
  self.mac_dst = mac_dst or self.mac_dst
  self.mac_src = mac_src or self.mac_src
  self.ether_type = ether_type or self.ether_type
  self.buf = packet or self.buf
  if not self.ether_type then
    return nil, "Unknown packet type."
  end
  self.frame_buf = self.mac_dst..self.mac_src..self.ether_type..self.buf
end
--- Parse an Ethernet frame.
-- @param frame string of the Ether frame.
-- @return mac_dst six-byte string of the destination MAC address.
-- @return mac_src six-byte string of the source MAC address.
-- @return packet string of the payload.
function Frame:ether_parse()
  if not self.frame_buf or #self.frame_buf < 14 then -- too short
    return false
  end
  self.mac_dst = string.sub(self.frame_buf, 1, 6)
  self.mac_src = string.sub(self.frame_buf, 7, 12)
  self.ether_type = u16(self.frame_buf, 12)
end

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
  if not packet then
    return o
  end
  o.buf = packet
  o.packet_len = packet_len
  o.ip_v = string.byte(o.buf) >> 4
  if o.ip_v == 4 and not o:ip_parse(force_continue) then
    return nil
  elseif o.ip_v == 6 and not o:ip6_parse(force_continue) then
    return nil
  end

  if o.ip_v == 6 then
    while o:ipv6_is_extension_header() do
      if o.ip6_data_offset >= o.packet_len or not o:ipv6_ext_header_parse(force_continue) then
        stdnse.debug1("Error while parsing IPv6 extension headers.")
        return o
      end
    end
    o.ip_p = o.ip6_nhdr
  end

  if o.ip_p == IPPROTO_TCP then
    if not o:tcp_parse(force_continue) then
      stdnse.debug1("Error while parsing TCP packet\n")
    end
  elseif o.ip_p == IPPROTO_UDP then
    if not o:udp_parse(force_continue) then
      stdnse.debug1("Error while parsing UDP packet\n")
    end
  elseif o.ip_p == IPPROTO_ICMP then
    if not o:icmp_parse(force_continue) then
      stdnse.debug1("Error while parsing ICMP packet\n")
    end
  elseif o.ip_p == IPPROTO_ICMPV6 then
    if not o:icmpv6_parse(force_continue) then
      stdnse.debug1("Error while parsing ICMPv6 packet\n")
    end
  end
  return o
end
--- Convert Version, Traffic Class and Flow Label to a 4-byte string.
-- @param ip6_tc Number stands for Traffic Class.
-- @param ip6_fl Number stands for Flow Label.
-- @return The first four-byte string of an IPv6 header.
local function ipv6_hdr_tc_fl(ip6_tc, ip6_fl)
  return (6 << 28) +
    ((ip6_tc & 0xFF) << 20) +
    (ip6_fl & 0xFFFFF)
end
--- Build an IPv6 packet.
-- @param src 16-byte string of the source IPv6 address.
-- @param dsr 16-byte string of the destination IPv6 address.
-- @param nx_hdr integer that represents next header.
-- @param h_limit integer that represents hop limit.
-- @param t_class integer that represents traffic class.
-- @param f_label integer that represents flow label.
function Packet:build_ipv6_packet(src, dst, nx_hdr, payload, h_limit, t_class, f_label)
  self.ether_type = ETHER_TYPE_IPV6
  self.ip_v = 6
  self.ip_bin_src = src or self.ip_bin_src
  self.ip_bin_dst = dst or self.ip_bin_dst
  self.ip6_nhdr = nx_hdr or self.ip6_nhdr
  self.l4_packet = payload or self.l4_packet
  self.ip6_tc = t_class or self.ip6_tc or 1
  self.ip6_fl = f_label or self.ip6_fl or 1
  self.ip6_hlimit = h_limit or self.ip6_hlimit or 255
  self.ip6_plen = #(self.exheader or "")+#(self.l4_packet or "")
  self.buf = (">I4I2BBc16c16"):pack(
    ipv6_hdr_tc_fl(self.ip6_tc, self.ip6_fl),
    self.ip6_plen, --payload length
    self.ip6_nhdr, --next header
    self.ip6_hlimit, --hop limit
    self.ip_bin_src, --Source
    self.ip_bin_dst) .. --dest
    (self.exheader or "")..
    (self.l4_packet or "")
end
--- Return true if and only if the next header is an known extension header.
-- @param nhdr Next header.
function Packet:ipv6_is_extension_header(nhdr)
  self.ip6_nhdr = nhdr or self.ip6_nhdr
  if self.ip6_nhdr == IPPROTO_HOPOPTS or
    self.ip6_nhdr == IPPROTO_DSTOPTS or
    self.ip6_nhdr == IPPROTO_ROUTING or
    self.ip6_nhdr == IPPROTO_FRAGMENT then
    return true
  end
  return nil
end
--- Count IPv6 checksum.
-- @return the checksum.
function Packet:count_ipv6_pseudoheader_cksum()
  local pseudoheader = (">c16c16I2xxxB"):pack(
    self.ip_bin_src, self.ip_bin_dst, #self.l4_packet, self.ip6_nhdr)
  local ck_content = pseudoheader .. self.l4_packet
  return in_cksum(ck_content)
end
--- Set ICMPv6 checksum.
function Packet:set_icmp6_cksum(check_sum)
  self.l4_packet = set_u16(self.l4_packet, 2, check_sum)
end
--- Build an ICMPv6 header.
-- @param icmpv6_type integer that represent ICMPv6 type.
-- @param icmpv6_code integer that represent ICMPv6 code.
-- @param icmpv6_payload string of the payload
-- @param ip_bin_src 16-byte string of the source IPv6 address.
-- @param ip_bin_dst 16-byte string of the destination IPv6 address.
function Packet:build_icmpv6_header(icmpv6_type, icmpv6_code, icmpv6_payload, ip_bin_src, ip_bin_dst)
  self.ip6_nhdr = IPPROTO_ICMPV6
  self.icmpv6_type = icmpv6_type or self.icmpv6_type
  self.icmpv6_code = icmpv6_code or self.icmpv6_code
  self.icmpv6_payload = icmpv6_payload or self.icmpv6_payload
  self.ip_bin_src = ip_bin_src or self.ip_bin_src
  self.ip_bin_dst = ip_bin_dst or self.ip_bin_dst

  self.l4_packet = ("BBxx"):pack(self.icmpv6_type, self.icmpv6_code) ..
    (self.icmpv6_payload or "")
  local check_sum = self:count_ipv6_pseudoheader_cksum()
  self:set_icmp6_cksum(check_sum)
end
--- Build an ICMPv6 Echo Request frame.
-- @param mac_src six-byte string of source MAC address.
-- @param mac_dst sis-byte string of destination MAC address.
-- @param ip_bin_src 16-byte string of source IPv6 address.
-- @param ip_bin_dst 16-byte string of destination IPv6 address.
-- @param id integer that represents Echo ID.
-- @param sequence integer that represents Echo sequence.
-- @param data string of Echo data.
-- @param tc integer that represents traffic class of IPv6 packet.
-- @param fl integer that represents flow label of IPv6 packet.
-- @param hop-limit integer that represents hop limit of IPv6 packet.
function Packet:build_icmpv6_echo_request(id, sequence, data, mac_src, mac_dst, ip_bin_src, ip_bin_dst, tc, fl, hop_limit)
  self.mac_src = mac_src or self.mac_src
  self.mac_dst = mac_dst or self.mac_dst

  self.ip_bin_src = ip_bin_src or self.ip_bin_src
  self.ip_bin_dst = ip_bin_dst or self.ip_bin_dst
  self.traffic_class = tc or 1
  self.flow_label = fl or 1
  self.ip6_hlimit = hop_limit or 255

  self.icmpv6_type = ICMP6_ECHO_REQUEST
  self.icmpv6_code = 0

  self.echo_id = id or self.echo_id or 0xdead
  self.echo_seq = sequence or self.echo_seq or 0xbeef
  self.echo_data = data or self.echo_data or ""

  self.icmpv6_payload = (">I2I2"):pack(self.echo_id, self.echo_seq) .. self.echo_data
end
--- Set an ICMPv6 option message.
function Packet:set_icmpv6_option(opt_type,msg)
  return string.char(opt_type, (#msg+2)/8) .. msg
end

--- Build an IPv4 packet.
-- @param src 4-byte string of the source IP address.
-- @param dst 4-byte string of the destination IP address.
-- @param payload string containing the IP payload
-- @param dsf byte that represents the differentiated services field
-- @param id integer that represents the IP identification
-- @param flags integer that represents the IP flags
-- @param off integer that represents the IP offset
-- @param ttl integer that represent the IP time to live
-- @param proto integer that represents the IP protocol
function Packet:build_ip_packet(src, dst, payload, dsf, id, flags, off, ttl, proto)
  self.ether_type = ETHER_TYPE_IPV4
  self.ip_v = 4
  self.ip_bin_src = src or self.ip_bin_src
  self.ip_bin_dst = dst or self.ip_bin_dst
  self.l3_packet = payload or self.l3_packet
  self.ip_dsf = dsf or self.ip_dsf or 0
  self.ip_p = proto or self.ip_p
  self.flags = flags or self.flags or 0 -- should be split into ip_rd, ip_df, ip_mv
  self.ip_id = id or self.ip_id or 0xbeef
  self.ip_off = off or self.ip_off or 0
  self.ip_ttl = ttl or self.ip_ttl or 255
  self.buf = (">BBI2I2BBBBI2c4c4"):pack(
    (self.ip_v << 4) + 20 / 4, -- version and header length
    self.ip_dsf,
    #self.l3_packet + 20,
    self.ip_id,
    self.flags,
    self.ip_off,
    self.ip_ttl,
    self.ip_p,
    0, -- checksum
    self.ip_bin_src,  --Source
    self.ip_bin_dst --dest
    )

  self.buf = set_u16(self.buf, 10, in_cksum(self.buf))
  self.buf = self.buf .. self.l3_packet
end
--- Build an ICMP header.
-- @param icmp_type integer that represent ICMPv6 type.
-- @param icmp_code integer that represent ICMPv6 code.
-- @param icmp_payload string of the payload
-- @param ip_bin_src 16-byte string of the source IPv6 address.
-- @param ip_bin_dst 16-byte string of the destination IPv6 address.
function Packet:build_icmp_header(icmp_type, icmp_code, icmp_payload, ip_bin_src, ip_bin_dst)
  self.icmp_type = icmp_type or self.icmp_type
  self.icmp_code = icmp_code or self.icmp_code
  self.icmp_payload = icmp_payload or self.icmp_payload
  self.ip_bin_src = ip_bin_src or self.ip_bin_src
  self.ip_bin_dst = ip_bin_dst or self.ip_bin_dst

  self.l3_packet = ("BBxx"):pack(self.icmp_type, self.icmp_code) ..
  (self.icmp_payload or "")
  self.l3_packet = set_u16(self.l3_packet, 2, in_cksum(self.l3_packet))
end
--- Build an ICMP Echo Request frame.
-- @param mac_src six-byte string of source MAC address.
-- @param mac_dst sis-byte string of destination MAC address.
-- @param ip_bin_src 16-byte string of source IPv6 address.
-- @param ip_bin_dst 16-byte string of destination IPv6 address.
-- @param id integer that represents Echo ID.
-- @param seq integer that represents Echo sequence.
-- @param data string of Echo data.
-- @param dsf integer that represents differentiated services field.
function Packet:build_icmp_echo_request(id, seq, data, mac_src, mac_dst, ip_bin_src, ip_bin_dst)
  self.mac_src = mac_src or self.mac_src
  self.mac_dst = mac_dst or self.mac_dst

  self.ip_p = IPPROTO_ICMP
  self.ip_bin_src = ip_bin_src or self.ip_bin_src
  self.ip_bin_dst = ip_bin_dst or self.ip_bin_dst

  self.icmp_type = ICMP_ECHO_REQUEST
  self.icmp_code = 0

  self.echo_id = id or self.echo_id or 0xdead
  self.echo_seq = seq or self.echo_seq or 0xbeef
  self.echo_data = data or self.echo_data or ""

  self.icmp_payload = (">I2I2"):pack(self.echo_id, self.echo_seq) .. self.echo_data
end


-- Helpers


local function _hex_str (x)
  return string.char(tonumber(x, 16))
end
--- Convert a MAC address string (like <code>"00:23:ae:5d:3b:10"</code>) to
-- a raw six-byte long.
-- @param str MAC address string.
-- @return Six-byte string.
function mactobin(str)
  if not str then
    return nil, "MAC was not specified."
  end
  return (str:gsub("(%x%x)[^%x]?", _hex_str))
end

--- Generate the link-local IPv6 address from the MAC address.
-- @param mac  MAC address string.
-- @return Link-local IPv6 address string.
function mac_to_lladdr(mac)
  if not mac then
    return nil, "MAC was not specified."
  end
  local interfier = string.char((string.byte(mac,1) | 0x02))..string.sub(mac,2,3).."\xff\xfe"..string.sub(mac,4,6)
  local ll_prefix = ipOps.ip_to_str("fe80::")
  return string.sub(ll_prefix,1,8)..interfier
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
-- @param index The beginning of the part of the packet to extract. The index
-- is 0-based. If omitted the default value is 0 (beginning of the string)
-- @param length The length of the part of the packet to extract. If omitted
-- the remaining contents from index to the end of the string are returned.
-- @return A string.
function Packet:raw(index, length)
  if not index then index = 0 end
  if not length then length = #self.buf-index end
  return self.buf:sub(index+1, index+1+length-1)
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
  self.ip_offset = 0
  if    #self.buf < 20 then -- too short
    stdnse.debug2("Packet.ip_parse: too short")
    return false
  end
  self.ip_v = (self:u8(self.ip_offset + 0) & 0xF0) >> 4
  self.ip_hl = (self:u8(self.ip_offset + 0) & 0x0F) -- header_length or data_offset
  if    self.ip_v ~= 4 then -- not ip
    stdnse.debug2("Packet.ip_parse: Not IPv4")
    return false
  end
  self.ip = true
  self.ip_tos = self:u8(self.ip_offset + 1)
  self.ip_len = self:u16(self.ip_offset + 2)
  self.ip_id = self:u16(self.ip_offset + 4)
  self.ip_off = self:u16(self.ip_offset + 6)
  self.ip_rf = (self.ip_off & 0x8000)~=0 -- true/false
  self.ip_df = (self.ip_off & 0x4000)~=0
  self.ip_mf = (self.ip_off & 0x2000)~=0
  self.ip_off = (self.ip_off & 0x1FFF) -- fragment offset
  self.ip_ttl = self:u8(self.ip_offset + 8)
  self.ip_p = self:u8(self.ip_offset + 9)
  self.ip_sum = self:u16(self.ip_offset + 10)
  self.ip_bin_src = self:raw(self.ip_offset + 12,4) -- raw 4-bytes string
  self.ip_bin_dst = self:raw(self.ip_offset + 16,4)
  self.ip_src = ipOps.str_to_ip(self.ip_bin_src) -- formatted string
  self.ip_dst = ipOps.str_to_ip(self.ip_bin_dst)
  self.ip_opt_offset = self.ip_offset + 20
  self.ip_options = self:parse_options(self.ip_opt_offset, ((self.ip_hl*4)-20))
  self.ip_data_offset = self.ip_offset + self.ip_hl*4
  return true
end
--- Parse an IPv6 packet header.
-- @param force_continue Ignored.
-- @return Whether the parsing succeeded.
function Packet:ip6_parse(force_continue)
  self.ip6_offset = 0
  if #self.buf < 40 then -- too short
    return false
  end
  self.ip_v = (self:u8(self.ip6_offset + 0) & 0xF0) >> 4
  if self.ip_v ~= 6 then -- not ipv6
    return false
  end
  self.ip6 = true
  self.ip6_tc = (self:u16(self.ip6_offset + 0) & 0x0FF0) >> 4
  self.ip6_fl = (self:u8(self.ip6_offset + 1) & 0x0F)*65536 + self:u16(self.ip6_offset + 2)
  self.ip6_plen = self:u16(self.ip6_offset + 4)
  self.ip6_nhdr = self:u8(self.ip6_offset + 6)
  self.ip6_hlimt = self:u8(self.ip6_offset + 7)
  self.ip_bin_src = self:raw(self.ip6_offset + 8, 16)
  self.ip_bin_dst = self:raw(self.ip6_offset + 24, 16)
  self.ip_src = ipOps.str_to_ip(self.ip_bin_src)
  self.ip_dst = ipOps.str_to_ip(self.ip_bin_dst)
  self.ip6_data_offset = 40
  return true
end
--- Pare an IPv6 extension header. Just jump over it at the moment.
-- @param force_continue Ignored.
-- @return Whether the parsing succeeded.
function Packet:ipv6_ext_header_parse(force_continue)
  local ext_hdr_len = self:u8(self.ip6_data_offset + 1)
  ext_hdr_len = ext_hdr_len*8 + 8
  self.ip6_data_offset = self.ip6_data_offset + ext_hdr_len
  self.ip6_nhdr = self:u8(self.ip6_data_offset)
  return true
end
--- Set the payload length field.
-- @param plen Payload length.
function Packet:ip6_set_plen(plen)
  self:set_u16(self.ip6_offset + 4, plen)
  self.ip6_plen = plen
end
--- Set the header length field.
function Packet:ip_set_hl(len)
  self:set_u8(self.ip_offset + 0, (self.ip_v << 4) | (len & 0x0F))
  self.ip_v = (self:u8(self.ip_offset + 0) & 0xF0) >> 4
  self.ip_hl = (self:u8(self.ip_offset + 0) & 0x0F) -- header_length or data_offset
end
--- Set the packet length field.
-- @param len Packet length.
function Packet:ip_set_len(len)
  self:set_u16(self.ip_offset + 2, len)
  self.ip_len = len
end
--- Set the packet identification field.
-- @param id packet ID.
function Packet:ip_set_id(id)
  self:set_u16(self.ip_offset + 4, id)
  self.ip_id = id
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
  self.ip_bin_src = self:raw(self.ip_offset + 12,4) -- raw 4-bytes string
end
--- Set the destination IP address.
-- @param binip The destination IP address as a byte string.
function Packet:ip_set_bin_dst(binip)
  local nrip = u32(binip, 0)
  self:set_u32(self.ip_offset + 16, nrip)
  self.ip_bin_dst = self:raw(self.ip_offset + 16,4)
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
  self.ip_options = self:parse_options(self.ip_opt_offset, ((self.ip_hl*4)-20))
  self.ip_data_offset = self.ip_offset + self.ip_hl*4
  if self.tcp then
    self.tcp_offset = self.ip_data_offset
  elseif self.icmp then
    self.icmp_offset = self.ip_data_offset
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
  self.icmp_offset = self.ip_data_offset
  if #self.buf < self.icmp_offset + 8 then -- let's say 8 bytes minimum
    return false
  end
  self.icmp = true
  self.icmp_type = self:u8(self.icmp_offset + 0)
  self.icmp_code = self:u8(self.icmp_offset + 1)
  self.icmp_sum = self:u16(self.icmp_offset + 2)

  if self.icmp_type == 3 or self.icmp_type == 4 or self.icmp_type == 11 or self.icmp_type == 12 then
    self.icmp_payload = true
    self.icmp_r0 = self:u32(self.icmp_offset + 4)
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
--- Parse an ICMPv6 packet header.
-- @param force_continue Ignored.
-- @return Whether the parsing succeeded.
function Packet:icmpv6_parse(force_continue)
  self.icmpv6_offset = self.ip6_data_offset
  if #self.buf < self.icmpv6_offset + 8 then -- let's say 8 bytes minimum
    return false
  end
  self.icmpv6 = true
  self.icmpv6_type = self:u8(self.icmpv6_offset + 0)
  self.icmpv6_code = self:u8(self.icmpv6_offset + 1)

  if self.icmpv6_type == ND_NEIGHBOR_SOLICIT then
    self.ns_target = self:raw(self.icmpv6_offset + 8, 16)
  end
  return true
end

----------------------------------------------------------------------------------------------------------------
-- Parse a TCP packet header.
-- @param force_continue Whether a short packet causes parsing to fail.
-- @return Whether the parsing succeeded.
function Packet:tcp_parse(force_continue)
  self.tcp = true
  self.tcp_offset = self.ip_data_offset or self.ip6_data_offset
  if #self.buf < self.tcp_offset + 4 then
    return false
  end
  self.tcp_sport = self:u16(self.tcp_offset + 0)
  self.tcp_dport = self:u16(self.tcp_offset + 2)
  if #self.buf < self.tcp_offset + 20 then
    if force_continue then
      return true
    else
      return false
    end
  end
  self.tcp_seq = self:u32(self.tcp_offset + 4)
  self.tcp_ack = self:u32(self.tcp_offset + 8)
  self.tcp_hl = (self:u8(self.tcp_offset+12) & 0xF0) >> 4 -- header_length or data_offset
  self.tcp_x2 = (self:u8(self.tcp_offset+12) & 0x0F)
  self.tcp_flags = self:u8(self.tcp_offset + 13)
  self.tcp_th_fin = (self.tcp_flags & 0x01)~=0 -- true/false
  self.tcp_th_syn = (self.tcp_flags & 0x02)~=0
  self.tcp_th_rst = (self.tcp_flags & 0x04)~=0
  self.tcp_th_push = (self.tcp_flags & 0x08)~=0
  self.tcp_th_ack = (self.tcp_flags & 0x10)~=0
  self.tcp_th_urg = (self.tcp_flags & 0x20)~=0
  self.tcp_th_ece = (self.tcp_flags & 0x40)~=0
  self.tcp_th_cwr = (self.tcp_flags & 0x80)~=0
  self.tcp_win = self:u16(self.tcp_offset + 14)
  self.tcp_sum = self:u16(self.tcp_offset + 16)
  self.tcp_urp = self:u16(self.tcp_offset + 18)
  self.tcp_opt_offset = self.tcp_offset + 20
  self.tcp_options = self:parse_options(self.tcp_opt_offset, ((self.tcp_hl*4)-20))
  self.tcp_data_offset = self.tcp_offset + self.tcp_hl*4

  if self.ip_len then
    self.tcp_data_length = self.ip_len - self.tcp_offset - self.tcp_hl*4
  else
    self.tcp_data_length = self.ip6_plen - self.tcp_hl*4
  end
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

    if opt.type == 0 then -- end of options
      eoo = true
    elseif opt.type == 2 then    -- MSS
      self.tcp_opt_mss = u16(opt.data, 0)
      self.tcp_opt_mtu = self.tcp_opt_mss + 40
    elseif opt.type == 3 then     -- widow scaling
      self.tcp_opt_ws  = u8(opt.data, 0)
    elseif opt.type == 8 then     -- timestamp
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
  local proto = self.ip_p
  local length = self.buf:len() - self.tcp_offset
  local b = self.ip_bin_src ..
    self.ip_bin_dst ..
    "\0" ..
    (">BI2"):pack(proto, length) ..
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
  self.udp_offset = self.ip_data_offset or self.ip6_data_offset
  if #self.buf < self.udp_offset + 4 then
    return false
  end
  self.udp_sport = self:u16(self.udp_offset + 0)
  self.udp_dport = self:u16(self.udp_offset + 2)
  if #self.buf < self.udp_offset + 8 then
    if force_continue then
      return true
    else
      return false
    end
  end
  self.udp_len = self:u16(self.udp_offset + 4)
  self.udp_sum = self:u16(self.udp_offset + 6)

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
  local proto = self.ip_p
  local length = self.buf:len() - self.udp_offset
  local b = self.ip_bin_src ..
    self.ip_bin_dst ..
    "\0" ..
    (">BI2"):pack(proto, length) ..
    self.buf:sub(self.udp_offset+1)

  self:udp_set_checksum(in_cksum(b))
end

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()
-- Byte setting functions
test_suite:add_test(unittest.equal(set_u8("abc", 1, 0x41), "aAc"), "set_u8")
test_suite:add_test(unittest.equal(set_u16("abcd", 2, 0x4142), "abAB"), "set_u16")
test_suite:add_test(unittest.equal(set_u32("abcdefg", 0, 0x41424344), "ABCDefg"), "set_u32")

-- Packet parsing
local packet1 = "\x45\x00\x00\x62\xaf\xbd\x40\x00\xe3\x06\x03\xf3\x03\x5e\x1e\xa5\xc0\xa8\x01\x3a\x01\xbb\xee\x3e\x74\xd2\x61\xbe\xd5\x66\xb1\x09\x80\x18\x00\x7a\x94\x22\x00\x00\x01\x01\x08\x0a\x73\xab\x53\x92\x05\xe3\x08\xc3\x17\x03\x03\x00\x29\x99\xff\x5d\x17\xe4\x26\x14\xb8\x53\xe3\x76\xdc\xba\xf9\x55\xf7\x52\x5f\xa2\x78\xc3\x4e\x9a\x31\x44\x2d\x67\x9c\x16\xea\x71\xf1\xdb\x0a\xdd\xc1\x92\x46\xa7\xdf\xde"
local pkt_parsed = Packet:new(packet1, #packet1, false)
test_suite:add_test (unittest.not_nil(pkt_parsed), "parse packet")

test_suite:add_test(unittest.equal(pkt_parsed:raw(), packet1), "parse to raw")

-- Checksum tests
pkt_parsed:ip_count_checksum()
test_suite:add_test(unittest.equal(pkt_parsed:raw(), packet1), "IP checksum")
pkt_parsed:tcp_count_checksum()
test_suite:add_test(unittest.equal(pkt_parsed:raw(), packet1), "TCP checksum")

-- TODO: UDP parsing/checksum
-- TODO: IPv6 parsing, ICMPv6 checksum
-- Basically, we need a lot more test coverage here.
return _ENV;
