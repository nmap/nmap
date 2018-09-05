local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

author = "jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}
description = [[
Obtains and prints an NTP server's monitor data.

Monitor data is a list of the most recently used (MRU) having NTP associations
with the target. Each record contains information about the most recent NTP
packet sent by a host to the target including the source and destination
addresses and the NTP version and mode of the packet. With this information it
is possible to classify associated hosts as Servers, Peers, and Clients.

A Peers command is also sent to the target and the peers list in the response
allows differentiation between configured Mode 1 Peers and clients which act
like Peers (such as the Windows W32Time service).

Associated hosts are further classified as either public or private.
Private hosts are those
having IP addresses which are not routable on the public Internet and thus can
help to form a picture about the topology of the private network on which the
target resides.

Other information revealed by the monlist and peers commands are the host with
which the target clock is synchronized and hosts which send Control Mode (6)
and Private Mode (7) commands to the target and which may be used by admins for
the NTP service.

It should be noted that the very nature of the NTP monitor data means that the
Mode 7 commands sent by this script are recorded by the target (and will often
appear in these results). Since the monitor data is a MRU list, it is probable
that you can overwrite the record of the Mode 7 command by sending an innocuous
looking Client Mode request. This can be achieved easily using Nmap:
<code>nmap -sU -pU:123 -Pn -n --max-retries=0 <target></code>

Notes:
* The monitor list in response to the monlist command is limited to 600 associations.
* The monitor capability may not be enabled on the target in which case you may receive an error number 4 (No Data Available).
* There may be a restriction on who can perform Mode 7 commands (e.g. "restrict noquery" in <code>ntp.conf</code>) in which case you may not receive a reply.
* This script does not handle authenticating and targets expecting auth info may respond with error number 3 (Format Error).
]]

---
-- @usage
-- nmap -sU -pU:123 -Pn -n --script=ntp-monlist <target>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 123/udp open  ntp     udp-response
-- | ntp-monlist:
-- |   Target is synchronised with 127.127.38.0 (reference clock)
-- |   Alternative Target Interfaces:
-- |       10.17.4.20
-- |   Private Servers (0)
-- |   Public Servers (0)
-- |   Private Peers (0)
-- |   Public Peers (0)
-- |   Private Clients (2)
-- |       10.20.8.69      169.254.138.63
-- |   Public Clients (597)
-- |       4.79.17.248     68.70.72.194    74.247.37.194   99.190.119.152
-- |       ...
-- |       12.10.160.20    68.80.36.133    75.1.39.42      108.7.58.118
-- |       68.56.205.98
-- |       2001:1400:0:0:0:0:0:1 2001:16d8:dd00:38:0:0:0:2
-- |       2002:db5a:bccd:1:21d:e0ff:feb7:b96f 2002:b6ef:81c4:0:0:1145:59c5:3682
-- |   Other Associations (1)
-- |_      127.0.0.1 seen 1949869 times. last tx was unicast v2 mode 7

-- This script uses the NTP sequence numbers and the 'more' bit found in
-- response packets in order to determine when to stop the reception loop. It
-- would be possible for a malicious target to tie-up this script by sending
-- a continuous stream of UDP datagrams.
-- Therefore MAXIMUM_EVIL has been defined to limit the number of malformed or
-- duplicate packets that will be processed before a target is rejected and
-- MAX_RECORDS simply limits the storage of valid looking NTP data to a sane
-- level.
local MAXIMUM_EVIL = 25
local MAX_RECORDS  = 1200

local TIMEOUT      = 5000 -- ms


---
-- ntp-monlist will run against the ntp service which only runs on UDP 123
--
portrule = shortport.port_or_service(123, 'ntp', {'udp'})

---
-- Send an NTPv2 Mode 7 'monlist' command to the target, receive any responses
-- and parse records from those responses. If the target responds favourably
-- then send a 'peers' command and parse the responses.  Finally, categorise the
-- discovered NTP associations (hosts) and output the interpreted results.
--
action = function(host, port)

  -- Define the request code and implementation numbers of the NTP request to
  -- send to the target.
  local REQ_MON_GETLIST_1 = 42
  local REQ_PEER_LIST     = 0
  local IMPL_XNTPD        = 3

  -- parsed records will be stored in this table.
  local records = {['peerlist'] = {}}

  -- send monlist command and fill the records table with the responses.
  local inum, rcode = IMPL_XNTPD, REQ_MON_GETLIST_1
  local sock = doquery(nil, host, port, inum, rcode, records)

  -- end here if there are zero records.
  if #records == 0 then
    if sock then sock:close() end
    return nil
  end

  -- send peers command and add the responses to records.peerlist.
  rcode = REQ_PEER_LIST
  sock = doquery(sock, host, port, inum, rcode, records)
  if sock then sock:close() end

  -- now we can interpret the collected records.
  local interpreted = interpret(records, host.ip)

  -- output.
  return summary(interpreted)

end


---
-- Sends NTPv2 Mode 7 requests to the target, receives any responses and parses
-- records from those responses.
--
-- @param  sock    Socket object which must be supplied in a connected state.
--                 nil may be supplied instead and a socket will be created.
-- @param  host    Nmap host table for the target.
-- @param  port    Nmap port table for the target.
-- @param  inum    NTP implementation number (i.e. 0, 2 or 3).
-- @param  rcode   NTP Mode 7 request code (e.g. 42 for 'monlist').
-- @param  records Table in which to store records parsed from responses.
-- @return sock    Socket object connected to the target.
--
function doquery(sock, host, port, inum, rcode, records)

  local target = ('%s%s%d'):format(
    host.ip, host.ip:match(':') and '.' or ':', port.number
  )
  records.badpkts  = records.badpkts or 0
  records.peerlist = records.peerlist or {}

  if #records + #records.peerlist >= MAX_RECORDS then
    stdnse.debug1('MAX_RECORDS has been reached for target %s - only processing what we have already!', target)
    if sock then sock:close() end
    return nil
  end

  -- connect a new socket if one wasn't supplied
  if not sock then
    sock = nmap.new_socket()
    sock:set_timeout(TIMEOUT)
    local constatus, conerr = sock:connect(host, port)
    if not constatus then
      stdnse.debug1('Error establishing a UDP connection for %s - %s', target, conerr)
      return nil
    end
  end

  -- send
  stdnse.debug2('Sending NTPv2 Mode 7 Request %d Implementation %d to %s.', rcode, inum, target)
  local ntpData = getPrivateMode(inum, rcode)
  local sendstatus, senderr = sock:send(ntpData)
  if not sendstatus then
    stdnse.debug1('Error sending NTP request to %s:%d - %s', host.ip, port.number, senderr)
    sock:close()
    return nil
  end

  local track = {
    ['evil_pkts'] = records.badpkts, -- a count of bad packets
    ['hseq']      = -1,     -- highest received seq number
    ['mseq']      = '|',    -- missing seq numbers
    ['errcond']   = false,  -- true if sock, ntp or sane response error exists
    ['rcv_again'] = false,  -- true if we should receive_bytes again (more bit is set or missing seq).
    ['target']    = target, -- target ip and port
    ['v']         = 2,      -- ntp version
    ['m']         = 7,      -- ntp mode
    ['c']         = rcode,  -- ntp request code
    ['i']         = inum    -- ntp request implementation number
  }

  -- receive and parse
  repeat
    -- receive any response
    local rcvstatus, response = sock:receive_bytes(1)
    -- check the response
    local packet_to_parse = check(rcvstatus, response, track)
    -- parse the response
    if not track.errcond then
      local remain = parse_v2m7(packet_to_parse, records)
      if remain > 0 then
        stdnse.debug1('MAX_RECORDS has been reached while parsing NTPv2 Mode 7 Code %d responses from the target %s.', rcode, target)
        track.rcv_again = false
      elseif remain == -1 then
        stdnse.debug1('Parsing of NTPv2 Mode 7 implementation number %d request code %d response from %s has not been implemented.', inum, rcode, target)
        track.rcv_again = false
      end
    end
    records.badpkts = records.badpkts + track.evil_pkts
    if records.badpkts >= MAXIMUM_EVIL then
      stdnse.debug1('Had %d bad packets from %s - Not continuing with this host!', target, records.badpkts)
      sock:close()
      return nil
    end

  until not track.rcv_again

  return sock

end


---
-- Generates an NTP Private Mode (7) request with the supplied implementation
-- number and request code.
--
-- @param  impl number - valid values are 0, 2 and 3 - defaults to 3
-- @param  requestCode number - defaults to 42
-- @return String request.
--
function getPrivateMode(impl, requestCode)
  local pay
  -- udp payload is 48 bytes.
  -- For a description of Mode 7 packets see NTP source file:
  -- include/ntp_request.h
  --
  -- Flags 8bits: 0x17
  --   (Response Bit: 0, More Bit: 0, Version Number 3bits: 2, Mode 3bits: 7)
  -- Authenticated Bit: 0, Sequence Number 7bits: 0
  -- Implementation Number 8bits: e.g. 0x03 (IMPL_XNTPD)
  -- Request Code 8bits: e.g. 0x2a (MON_GETLIST_1)
  -- Err 4bits: 0, Number of Data Items 12bits: 0
  -- MBZ 4bits: 0, Size of Data Items 12bits: 0
  return string.char(
    0x17, 0x00, impl or 0x03, requestCode or 0x2a,
    0x00, 0x00, 0x00, 0x00
  )
  -- Data 40 Octets: 0
  .. ("\x00"):rep(40)
  -- The following are optional if the Authenticated bit is set:
  -- Encryption Keyid 4 Octets: 0
  -- Message Authentication Code 16 Octets (MD5): 0
end


---
-- Checks that the response from the target is a valid NTP response.
--
-- Starts by checking that the socket read was successful and then creates a
-- packet object from the response (with dummy IP and UDP headers).  Then
-- perform checks that ensure that the response is of the expected type and
-- length, that the records in the response are of the correct size and that
-- the response is part of a sequence of 1 or more responses and is not a
-- duplicate.
--
-- @param  status   boolean returned from a socket read operation.
-- @param  response string response returned from a socket operation.
-- @param  track    table used for tracking a sequence of NTP responses.
-- @return A Packet object ready for parsing or
--         nil if the response does not pass all checks.
--
function check(status, response, track)

  -- check for socket error
  if not status then
    track.errcond = true
    track.rcv_again = false
    if track.rcv_again then -- we were expecting more responses
      stdnse.debug1('Socket error while reading from %s - %s', track.target, response)
    end
    return nil
  end

  -- reset flags
  track.errcond   = false
  track.rcv_again = false

  -- create a packet object
  local pkt = make_udp_packet(response)
  if pkt == nil then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Failed to create a Packet object with response from %s', track.target)
    return nil
  end

  -- off is the start of udp payload i.e. NTP
  local off = 28

  -- NTP sanity checks

  local val

  -- NTP data must be at least 8 bytes
  val = response:len()
  if val < 8 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Expected a response of at least 8 bytes from %s, got %d bytes.', track.target, val)
    return nil
  end

  -- response bit set
  if (pkt:u8(off) >> 7) ~= 1 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Bad response from %s - did not have response bit set.', track.target)
    return nil
  end
  -- version is as expected
  val = (pkt:u8(off) >> 3) & 0x07
  if val ~= track.v then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Bad response from %s - expected NTP version %d, got %d', track.target, track.v, val)
    return nil
  end
  -- mode is as expected
  val = pkt:u8(off) & 0x07
  if val ~= track.m then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Bad response from %s - expected NTP mode %d, got %d', track.target, track.m, val)
    return nil
  end
  -- implementation number is as expected
  val = pkt:u8(off+2)
  if val ~= track.i then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Bad response from %s - expected NTP implementation number %d, got %d', track.target, track.i, val)
    return nil
  end
  -- request code is as expected
  val = pkt:u8(off+3)
  if val ~= track.c then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Bad response from %s - expected NTP request code %d got %d.', track.target, track.c, val)
    return nil
  end
  -- NTP error conditions - defined codes are not evil (bogus codes are).
  local fail, msg = false
  local err = (pkt:u8(off+4) >> 4) & 0x0f
  if err == 0 then
    -- NoOp
  elseif err == 1 then
    fail = true
    msg = 'Incompatible Implementation Number'
  elseif err == 2 then
    fail = true
    msg = 'Unimplemented Request Code'
  elseif err == 3 then
    fail = true
    msg = 'Format Error' -- could be that auth is required - we didn't provide it.
  elseif err == 4 then
    fail = true
    msg = 'No Data Available' -- monitor not enabled or nothing in mru list.
  elseif err == 5 or err == 6 then
    fail = true
    msg = 'I don\'t know'
  elseif err == 7 then
    fail = true
    msg = 'Authentication Failure'
  elseif err > 7 then
    fail = true
    track.evil_pkts = track.evil_pkts+1
    msg = 'Bogus Error Code!' -- should not happen...
  end
  if fail then
    track.errcond = true
    stdnse.debug1('Response from %s was NTP Error Code %d - "%s"', track.target, err, msg)
    return nil
  end

  -- length checks - the data (number of items * size of an item) should be
  -- 8 <= data <= 500 and each data item should be of correct length for the
  -- implementation and request type.

  -- Err 4 bits, Number of Data Items 12 bits
  local icount = pkt:u16(off+4) & 0xFFF
  -- MBZ 4 bits, Size of Data Items: 12 bits
  local isize  = pkt:u16(off+6) & 0xFFF
  if icount < 1 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('Expected at least one record from %s.', track.target)
    return nil
  elseif icount*isize + 8 > response:len() then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('NTP Mode 7 response from %s has invalid count (%d) and/or size (%d) values.', track.target, icount, isize)
    return nil
  elseif icount*isize > 500 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1('NTP Mode 7 data section is larger than 500 bytes (%d) in response from %s.', icount*isize, track.target)
    return nil
  end

  if track.c == 42 and track.i == 3 and isize ~= 72 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1(
      'Expected item size of 72 bytes (got %d) for request code 42 implementation number 3 in response from %s.',
      isize, track.target
    )
    return nil
  elseif track.c == 0 and track.i == 3 and isize ~= 32 then
    track.errcond = true
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1(
      'Expected item size of 32 bytes (got %d) for request code 0 implementation number 3 in response from %s.',
      isize, track.target
    )
    return nil
  end

  -- is the response out of sequence, a duplicate or is it peachy
  local seq = pkt:u8(off+1) & 0x7f
  if seq == track.hseq+1 then -- all good
    track.hseq = track.hseq+1
  elseif track.mseq:match(('|%d|'):format(seq)) then -- one of our missing seq#
    track.mseq:gsub(('|%d|'):format(seq), '|', 1)
    stdnse.debug3('Response from %s with sequence number %s was previously missing.', -- this never seems to happen!
      track.target, seq
    )
  elseif seq > track.hseq then -- some seq# have gone missing
    for i=track.hseq+1, seq-1 do
      track.mseq = ('%s%d|'):format(track.mseq, i)
    end
    stdnse.debug3(
      'Response from %s was out of sequence - expected #%d but got #%d (missing:%s)',
      track.target, track.hseq+1, seq, track.mseq
    )
    track.hseq = seq
  else -- seq <= hseq !duplicate!
    track.evil_pkts = track.evil_pkts+1
    stdnse.debug1(
      'Response from %s had a duplicate sequence number - dropping it.',
      track.target
    )
    return nil
  end

  -- if the more bit is set or if we have missing sequence numbers then we'll
  -- want to receive more packets after parsing this one.
  local more = (pkt:u8(off) >> 6) & 0x01
  if more == 1 then
    track.rcv_again = true
  elseif track.mseq:len() > 1 then
    track.rcv_again = true
  end

  return pkt

end


---
-- Returns a Packet Object generated with dummy IP and UDP headers and the
-- supplied UDP payload so that the payload may be conveniently parsed using
-- packet library methods. The dummy headers contain the barest information
-- needed to appear valid to packet.lua
--
-- @param  response String UDP payload.
-- @return Packet object or nil in case of an error.
--
function make_udp_packet(response)

  -- udp len
  local udplen = 8 + response:len()
  -- ip len
  local iplen  = 20 + udplen

  -- dummy headers
  -- ip
  local dh = "\x45\x00" -- IPv4, 20-byte header, no DSCP, no ECN
  .. string.pack('>I2', iplen) -- total length
  .. "\x00\x00" -- IPID 0
  .. "\x40\x00" -- DF
  .. "\x40\x11" -- TTL 0x40, UDP (proto 17)
  .. "\x00\x00" -- checksum 0
  .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Source, destination 0.0.0.0
  .. "\x00\x00\x00\x00" -- UDP source, dest port 0
  .. string.pack('>I2', udplen) -- UDP length
  .. "\x00\x00" -- UDP checksum 0

  return packet.Packet:new(dh .. response, iplen)

end


---
-- Invokes parsing routines for NTPv2 Mode 7 response packets based on the
-- implementation number and request code defined in the response.
--
-- @param  pkt    Packet Object to be parsed.
-- @param  recs   Table to hold the accumulated records parsed from supplied
--                packet objects.
-- @return Number of records not parsed from the packet (usually zero) or
--         -1 if the response does not have an associated parsing routine.
--
function parse_v2m7(pkt, recs)
  local off = pkt.udp_offset + 8
  local impl = pkt:u8(off+2)
  local code = pkt:u8(off+3)
  if (impl == 3 or impl == 2) and code == 42 then
    return parse_monlist_1(pkt, recs)
  elseif (impl == 3 or impl == 2) and code == 0 then
    return parse_peerlist(pkt, recs)
  else
    return -1
  end
end


---
-- Parsed records from the supplied monitor list packet into the supplied table
-- of accumulated records.
--
-- The supplied response packets should be NTPv2 Mode 7 implementation number 2
-- or 3 and request code 42.
-- The fields parsed are the source and destination IP addresses, the count of
-- times the target has seen the host, the method of transmission (uni|broad|
-- multicast), NTP Version and Mode of the last packet received by the target
-- from the host.
--
-- @param  pkt  Packet object to extract monitor records from.
-- @param  recs A table of accumulated monitor records for storage of parsed
--              records.
-- @return Number of records not parsed from the packet which will be zero
--         except when MAX_RECORDS is reached.
--
function parse_monlist_1(pkt, recs)

  local off = pkt.udp_offset + 8 -- beginning of NTP
  local icount = pkt:u16(off+4) & 0xFFF
  local isize  = pkt:u16(off+6) & 0xFFF
  local remaining = icount

  off = off+8 -- beginning of data section

  for i=1, icount, 1 do
    if #recs + #recs.peerlist >= MAX_RECORDS then
      return remaining
    end
    local pos = off + isize * (i-1) -- beginning of item
    local t = {}

    -- src and dst addresses
    -- IPv4 if impl == 2 or v6 flag is not set
    if isize == 32 or pkt:u8(pos+32) ~= 1 then -- IPv4
      local saddr = ipOps.str_to_ip(pkt:raw(pos+16, 4))
      local daddr = ipOps.str_to_ip(pkt:raw(pos+20, 4))
      t.saddr = saddr
      t.daddr = daddr
    else -- IPv6
      local saddr = {}
      for j=40, 54, 2 do
        saddr[#saddr+1] = stdnse.tohex(pkt:u16(pos+j))
      end
      t.saddr = table.concat(saddr, ':')
      local daddr = {}
      for j=56, 70, 2 do
        daddr[#daddr+1] = stdnse.tohex(pkt:u16(pos+j))
      end
      t.daddr = table.concat(daddr, ':')
    end

    t.count   = pkt:u32(pos+12)
    t.flags   = pkt:u32(pos+24)
    -- I've seen flags be wrong-endian just once. why? I really don't know.
    -- Some implementations are not doing htonl for this field?
    if t.flags > 0xFFFFFF then
      -- only concerned with the high order byte
      t.flags = t.flags >> 24
    end
    t.mode    = pkt:u8(pos+30)
    t.version = pkt:u8(pos+31)
    recs[#recs+1] = t
    remaining = remaining -1
  end

  return remaining
end


---
-- Parsed records from the supplied peer list packet into the supplied table of
-- accumulated records.
--
-- The supplied response packets should be NTPv2 Mode 7 implementation number 2
-- or 3 and request code 0.
-- The fields parsed are the source IP address and the peer information flag.
--
-- @param  pkt  Packet object to extract peer records from.
-- @param  recs A table of accumulated monitor and peer records for storage of
--              parsed records.
-- @return Number of records not parsed from the packet which will be zero
--         except when MAX_RECORDS is reached.
--
function parse_peerlist(pkt, recs)

  local off = pkt.udp_offset + 8 -- beginning of NTP
  local icount = pkt:u16(off+4) & 0xFFF
  local isize  = pkt:u16(off+6) & 0xFFF
  local remaining = icount

  off = off+8 -- beginning of data section

  for i=0, icount-1, 1 do
    if #recs + #recs.peerlist >= MAX_RECORDS then
      return remaining
    end
    local pos = off + (i * isize) -- beginning of item
    local t = {}

    -- src address
    -- IPv4 if impl == 2 or v6 flag is not set
    if isize == 8 or pkt:u8(pos+8) ~= 1 then
      local saddr = ipOps.str_to_ip(pkt:raw(pos, 4))
      t.saddr = saddr
    else -- IPv6
      local saddr = {}
      for j=16, 30, 2 do
        saddr[#saddr+1] = stdnse.tohex(pkt:u16(pos+j))
      end
      t.saddr = table.concat(saddr, ':')
    end

    t.flags = pkt:u8(pos+7)
    table.insert(recs.peerlist, t)
    remaining = remaining -1
  end

  return remaining
end


---
-- Interprets the supplied records to discover information about the target
-- NTP associations.
--
-- Associations are categorised as NTP Servers, Peers and Clients based on the
-- Mode of packets sent to the target.  Alternative target interfaces are
-- recorded as well as the transmission mode of packets sent to the target (i.e.
-- unicast, broadcast or multicast).
--
-- @param  recs     A table of accumulated monitor and peer records for storage
--                  of parsed records.
-- @param  targetip String target IP address (e.g. host.ip)
-- @return Table of interpreted results with fields such as servs, clients,
--         peers, ifaces etc.
--
function interpret(recs, targetip)
  local txtyp = {
    ['1'] = 'unicast',
    ['2'] = 'broadcast',
    ['4'] = 'multicast'
  }
  local t   = {}
  t.servs   = {['pub']={['4']={},['6']={}}, ['prv']={['4']={},['6']={}}}
  t.peers   = {['pub']={['4']={},['6']={}}, ['prv']={['4']={},['6']={}}}
  t.porc    = {['pub']={['4']={},['6']={}}, ['prv']={['4']={},['6']={}}}
  t.clients = {['pub']={['4']={},['6']={}}, ['prv']={['4']={},['6']={}}}
  t.casts   = {['b']={['4']={},['6']={}}, ['m']={['4']={},['6']={}}}
  t.ifaces  = {['4']={},['6']={}}
  t.other   = {}
  t.sync    = ''
  if #recs.peerlist > 0 then
    t.have_peerlist = true
    recs.peerhash = {}
    for _, peer in ipairs(recs.peerlist) do
        recs.peerhash[peer.saddr] = peer
    end
  else
    t.have_peerlist = false
  end

  for _, r in ipairs(recs) do
    local vis = ipOps.isPrivate(r.saddr) and 'prv' or 'pub'
    local af = r.saddr:match(':') and '6' or '4'

    -- is the host a client, peer, server or other?
    if r.mode == 3 then
      table.insert(t.clients[vis][af], r.saddr)
    elseif r.mode == 4 then
      table.insert(t.servs[vis][af], r.saddr)
    elseif r.mode == 2 then
      table.insert(t.peers[vis][af], r.saddr)
    elseif r.mode == 1 then

      -- if we have a list of peers we can distinguish between mode 1 peers and
      -- mode 1 peers that are really clients (i.e. not configured as peers).
      if t.have_peerlist then
        if recs.peerhash[r.saddr] then
          table.insert(t.peers[vis][af], r.saddr)
        else
          table.insert(t.clients[vis][af], r.saddr)
        end
      else
        table.insert(t.porc[vis][af], r.saddr)
      end

    elseif r.mode == 5 then
      table.insert(t.servs[vis][af], r.saddr)
    else
      local tx = tostring(r.flags)
      table.insert(
        t.other,
        ('%s%s seen %d time%s. last tx was %s v%d mode %d'):format(
          r.saddr, _ == 1 and ' (You?)' or '', r.count,
          r.count > 1 and 's' or '',
          txtyp[tx] or tx, r.version, r.mode
        )
      )
    end

    local function isLoopback(addr)
      if addr:match(':') then
        if ipOps.compare_ip(addr, 'eq', '::1') then return true end
      elseif addr:match('^127') then
        return true
      end
      return false
    end

    -- destination addresses are target interfaces or broad/multicast addresses.
    if not isLoopback(r.daddr) then
      if r.flags == 1 then
        t.ifaces[af][r.daddr] = r.daddr
      elseif r.flags == 2 then
        t.casts.b[af][r.daddr] = r.daddr
      elseif r.flags == 4 then
        t.casts.m[af][r.daddr] = r.daddr
      else -- shouldn't happen
        stdnse.debug1(
          'Host associated with %s had transmission flag value %d - Strange!',
          targetip, r.flags
        )
      end
    end

  end -- for

  local function isTarget(addr, target)
    local targ_af = target:match(':') and 6 or 4
    local test_af = addr:match(':') and 6 or 4
    if test_af ~= targ_af then return false end
    if targ_af == 4 and addr == target then return true end
    if targ_af == 6
    and (ipOps.compare_ip(addr, 'eq', target)) then return true end
    return false
  end

  -- reorganise ifaces and casts tables
  local _ = {}
  for k, v in pairs(t.ifaces['4']) do
    if not isTarget(v, targetip) then
      _[#_+1] = v
    end
  end
  t.ifaces['4'] = _
  _ = {}
  for k, v in pairs(t.ifaces['6']) do
    if not isTarget(v, targetip) then
      _[#_+1] = v
    end
  end
  t.ifaces['6'] = _
  _ = {}
  for k, v in pairs(t.casts.b['4']) do
    _[#_+1] = v
  end
  t.casts.b['4'] = _
  _ = {}
  for k, v in pairs(t.casts.b['6']) do
    _[#_+1] = v
  end
  t.casts.b['6'] = _
  _ = {}
  for k, v in pairs(t.casts.m['4']) do
    _[#_+1] = v
  end
  t.casts.m['4'] = _
  _ = {}
  for k, v in pairs(t.casts.m['6']) do
    _[#_+1] = v
  end
  t.casts.m['6'] = _

  -- Single out the server to which the target is synched.
  -- Note that this server may not even appear in the monlist - it depends how
  -- busy the server is.
  if t.have_peerlist then
    for _, peer in ipairs(recs.peerlist) do
      if (peer.flags & 0x2) == 0x2 then
        t.sync = peer.saddr
        if peer.saddr:match('^127') then -- always IPv4, never IPv6!
          t.sync = t.sync .. ' (reference clock)'
        end
        break
      end
    end
  end

  return t

end


---
-- Outputs the supplied table of interpreted records.
--
-- @param  t Table of interpreted records as returned from interpret().
-- @return String script output.
--
function summary(t)

  local o = {}
  local count = 0
  local vbs = nmap.verbosity()

  -- Target is Synchronised with:
  if t.sync ~= '' then
    table.insert(o, ('Target is synchronised with %s'):format(t.sync))
  end

  -- Alternative Target Interfaces
  if #t.ifaces['4'] > 0 or #t.ifaces['6'] > 0 then
    table.insert(o,
      {
        ['name'] = 'Alternative Target Interfaces:',
        output_ips(t.ifaces)
      }
    )
  end

  -- Target listens to Broadcast Addresses
  if #t.casts.b['4'] > 0 or #t.casts.b['6'] > 0 then
    table.insert(o,
      {
        ['name'] = 'Target listens to Broadcast Addresses:',
        output_ips(t.casts.b)
      }
    )
  end

  -- Target listens to Multicast Addresses
  if #t.casts.m['4'] > 0 or #t.casts.m['6'] > 0 then
    table.insert(o,
      {
        ['name'] = 'Target listens to Multicast Addresses:',
        output_ips(t.casts.m)
      }
    )
  end

  -- Private Servers
  count = #t.servs.prv['4']+#t.servs.prv['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Private Servers (%d)'):format(count),
        output_ips(t.servs.prv)
      }
    )
  end
  -- Public Servers
  count = #t.servs.pub['4']+#t.servs.pub['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Public Servers (%d)'):format(count),
        output_ips(t.servs.pub)
      }
    )
  end

  -- Private Peers
  count = #t.peers.prv['4']+#t.peers.prv['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Private Peers (%d)'):format(count),
        output_ips(t.peers.prv)
      }
    )
  end
  -- Public Peers
  count = #t.peers.pub['4']+#t.peers.pub['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Public Peers (%d)'):format(count),
        output_ips(t.peers.pub)
      }
    )
  end

  -- Private Peers or Clients
  count = #t.porc.prv['4']+#t.porc.prv['6']
  if not t.have_peerlist and (count > 0 or vbs > 1) then
    table.insert(o,
      {
        ['name'] = ('Private Peers or Clients (%d)'):format(count),
        output_ips(t.porc.prv)
      }
    )
  end
  -- Public Peers or Clients
  count = #t.porc.pub['4']+#t.porc.pub['6']
  if not t.have_peerlist and (count > 0 or vbs > 1) then
    table.insert(o,
      {
        ['name'] = ('Public Peers or Clients (%d)'):format(count),
        output_ips(t.porc.pub)
      }
    )
  end

  -- Private Clients
  count = #t.clients.prv['4']+#t.clients.prv['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Private Clients (%d)'):format(count),
        output_ips(t.clients.prv)
      }
    )
  end
  -- Public Clients
  count = #t.clients.pub['4']+#t.clients.pub['6']
  if count > 0 or vbs > 1 then
    table.insert(o,
      {
        ['name'] = ('Public Clients (%d)'):format(count),
        output_ips(t.clients.pub)
      }
    )
  end

  -- Other
  count = #t.other
  if count > 0 then
    table.insert(o,
      {
        ['name'] = ('Other Associations (%d)'):format(count),
        t.other
      }
    )
  end

  return stdnse.format_output(true, o)

end


---
-- Sorts and combines a set of IPv4 and IPv6 addresses into a table of rows.
-- IPv4 addresses are ascending-sorted numerically and arranged in four columns
-- and IPv6 appear in subsequent rows, sorted and arranged to fit as many
-- addresses into a row as possible without the need for wrapping.
--
-- @param  t Table containing two subtables indexed as '4' and '6' containing
--           a list of IPv4 and IPv6 addresses respectively.
-- @return Table where each entry is a row of sorted and arranged IP addresses.
--
function output_ips(t)

  if #t['4'] < 1 and #t['6'] < 1 then return nil end

  local o = {}

  -- sort and tabulate IPv4 addresses
  table.sort(t['4'], function(a,b) return ipOps.compare_ip(a, "lt", b) end)
  local limit = #t['4']
  local cols = 4
  local rows = math.ceil(limit/cols)
  local numlast = limit - cols*rows + cols
  local pad4 = (' '):rep(15)
  local index = 0
  for c=1, cols, 1 do
    for r=1, rows, 1 do
      if r == rows and c > numlast then break end
      index = index+1
      o[r] = o[r] or ''
      local padlen = pad4:len() - t['4'][index]:len()
      o[r] = ('%s%s%s '):format(o[r], t['4'][index], pad4:sub(1, padlen))
    end
  end

  -- IPv6
  -- Rows are allowed to be 71 chars wide
  table.sort(t['6'], function(a,b) return ipOps.compare_ip(a, "lt", b) end)
  local i = 1
  local limit = #t['6']
  while i <= limit do
    local work = {}
    local len = 0
    local j = i
    repeat
      if not t['6'][j] then j = j-1; break end
      len = len + t['6'][j]:len() + 1
      if len > 71 then
        j = j-1
      else
        j = j+1
      end
    until len > 71
    for n = i, j, 1 do
      work[#work+1] = t['6'][n]
    end
    o[#o+1] = table.concat(work, ' ')
    i = j+1
  end
  return o
end
