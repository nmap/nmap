description = [[
Tries to discover firewall rules using an IP TTL expiration technique known
as firewalking.

The scan requires a firewall (or "gateway") and a metric (or "target").
For each filtered port on the target, send a probe with an IP TTL one greater
than the number of hops to the gateway. The TTL can be given in two ways:
directly with the <code>firewalk.ttl</code> script argument, or indirectly with
the <code>firewalk.gateway</code> script argument. For
<code>firewalk.gateway</code>, Nmap must be run with the
<code>--traceroute</code> option and the gateway must appear as one of the
traceroute hops.

If the probe is forwarded by the gateway, then we can expect to receive an
ICMP_TIME_EXCEEDED reply from the gateway next hop router, or eventually the
target if it is directly connected to the gateway. Otherwise, the probe will
timeout. As for UDP scans, this process can be quite slow if lots of ports are
blocked by the gateway.

From an original idea of M. Schiffman and D. Goldsmith, authors of the
firewalk tool.
]]


---
-- @usage
-- nmap --script firewalk --script-args firewalk.gateway=a.b.c.d --traceroute target
-- @usage
-- nmap --script firewalk --script-args firewalk.ttl=7 target
--
-- @args firewalk.gateway IP address of the tested firewall. Must be present in the traceroute results.
-- @args firewalk.ttl value of the TTL to use. Should be one greater than the
-- number of hops to the gateway. In case both <code>firewalk.ttl</code> and
-- <code>firewalk.gateway</code> IP address are
-- supplied, <code>firewalk.gateway</code> is ignored.
--
-- @output
-- | firewalk:
-- | PROTOCOL  FORWARDED PORTS
-- | udp       123,137,161
-- |_tcp       21-80,443
--


-- 08/28/2010
author = "Henri Doreau"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


require('bin')
require('packet')
require('tab')


local ICMP_TIME_EXCEEDED = 11

-- number of retries for unanswered probes
local MAX_RETRIES = 2

--
-- Protocol specific functions are broken down per protocol, in separate tables.
-- This design eases the addition of new protocols
--

--- TCP related functions
local tcp_funcs = {
  --- perform layer 4 validation: compare TCP ports between two packets
  -- @param ip a TCP packet
  -- @param orig the reference TCP packet
  -- @return wether source and destination ports are the same for the two
  -- packets or not.
  l4check = function(ip, orig)
    return ip.tcp_sport == orig.tcp_sport and ip.tcp_dport == orig.tcp_dport
  end,

  --- update informations of a generic TCP packet
  -- @param ip the IP packet to update
  -- @param dport the new TCP destination port to set
  updatepkt = function(ip, dport)
    ip:tcp_set_sport(math.random(0x401, 0xffff))
    ip:tcp_set_dport(dport)
    ip:tcp_set_seq(math.random(1, 0x7fffffff))
    ip:tcp_count_checksum()
  end,

  --- create a generic TCP probe packet, with IP ttl and destination port set to zero
  -- @param host Host object that represents the destination
  -- @return the newly crafted IP packet
  genericpkt = function(host)
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0000 0000 0000 0000 6002 0c00 0000 0000 0204 05b4"
    )
    local ip = packet.Packet:new(pktbin, pktbin:len())
    ip:tcp_parse(false)
    ip:ip_set_bin_src(host.bin_ip_src)
    ip:ip_set_bin_dst(host.bin_ip)

    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
    ip.ip_p = packet.IPPROTO_TCP
    ip:ip_set_len(pktbin:len())

    return ip
  end,

}

-- UDP related functions
local udp_funcs = {
  --- perform layer 4 validation: compare UDP ports between two packets
  -- @param ip a TCP packet
  -- @param orig the reference UDP packet
  -- @return wether source and destination ports are the same for the two
  -- packets or not.
  l4check = function(ip, orig)
    return ip.udp_sport == orig.udp_sport and ip.udp_dport == orig.udp_dport
  end,

  --- update informations of a generic UDP packet
  -- @param ip the IP packet to update
  -- @param dport the new UDP destination port to set
  updatepkt = function(ip, dport)
    ip:udp_set_sport(math.random(0x401, 0xffff))
    ip:udp_set_dport(dport)
    ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
    ip:udp_count_checksum()
  end,

  --- create a generic UDP probe packet, with IP ttl and destination port set to zero
  -- @param host Host object that represents the destination
  -- @return the newly crafted IP packet
  genericpkt = function(host)
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0800 0000"
    )
    local ip = packet.Packet:new(pktbin, pktbin:len())

    ip:udp_parse(false)
    ip:ip_set_bin_src(host.bin_ip_src)
    ip:ip_set_bin_dst(host.bin_ip)

    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_UDP)
    ip.ip_p = packet.IPPROTO_UDP
    ip:ip_set_len(pktbin:len())

    return ip
  end,
}

-- list of supported protocols
local supported_protocols = {
  tcp = tcp_funcs,
  udp = udp_funcs,
}

-- cache the currently tested protocol for the whole script
local Protocol


--- ensure that the catched reply is a valid icmp time exceeded
-- @param reply the packet from the probed target
-- @param orig the sent probe
-- @return wether the reply appears to be valid or not
local function checkpkt(reply, orig)
  local ip = packet.Packet:new(reply, reply:len())

  if ip.ip_p ~= packet.IPPROTO_ICMP or ip.icmp_type ~= ICMP_TIME_EXCEEDED then
    return false
  end

  local is = ip.buf:sub(ip.icmp_offset + 9)
  local ip2 = packet.Packet:new(is, is:len(), true)

  -- Check sent packet against ICMP payload
  if ip2.ip_p == orig.ip_p and
    ip2.ip_bin_src == orig.ip_bin_src and
    ip2.ip_bin_dst == orig.ip_bin_dst then

    -- check layer 4 protocols ports
    return Protocol.l4check(ip2, orig)
  end

  return false
end

--- set destination port and ip ttl to a generic probe packet
-- @param ip the ip object
-- @param dport the layer 4 destination port
-- @param ttl the ip ttl to set
local function updatepkt(ip, dport, ttl)
  ip:ip_set_ttl(ttl)

  -- call the protocol specific function to update the layer 4 destination port
  Protocol.updatepkt(ip, dport)

  ip:ip_count_checksum()
end

--- get the list of ports to probe
-- @param host Host object that represents the targetted host
-- @return array of ports to probe, sorted per protocol
local function getports(host)
  local ports = {}
  local combos = {
    {"tcp", "filtered"},
    {"udp", "open|filtered"}
  }

  for _, combo in ipairs(combos) do
    local port = nil
    local proto = combo[1]
    local state = combo[2]

    ports[proto] = {}

    repeat
      port = nmap.get_ports(host, port, proto, state)
      if port then
        table.insert(ports[proto], port.number)
      end
    until not port
  end

  return ports
end

--- store the firewalk ports into the registry
-- @param host Host object that represents the targetted host
-- @param ports list of ports to firewalk
local function setregs(host, ports)
  if not nmap.registry[host.ip] then
    nmap.registry[host.ip] = {}
  end
  nmap.registry[host.ip]['firewalk_ports'] = ports
end

--- host rule, check for requirements before to launch the script
hostrule = function(host)
  -- firewalk requires privileges to run
  if not nmap.is_privileged() then
    if not nmap.registry['firewalk'] then
      nmap.registry['firewalk'] = {}
    end
    if nmap.registry['firewalk']['rootfail'] then
      return false
    end
    nmap.registry['firewalk']['rootfail'] = true
    if nmap.verbosity() > 0 then
      nmap.log_write("stdout", "FIREWALK: not running for lack of privileges")
    end
    return false
  end
  if not host.interface then
    return false
  end
  -- get the list of ports to probe
  local ports = getports(host)
  local nb_ports = 0
  for proto in pairs(ports) do
    nb_ports = nb_ports + #ports[proto]
  end
  -- nothing to probe: cancel the execution
  if nb_ports < 1 then
    return false
  end
  setregs(host, ports)
  return true
end

--- bind the scan to the supplied ttl if given or to gateway(ttl) + 1
-- @param host Host object that represents the targetted host
-- @return the value of the ttl to use in our probes (or nil on error)
local function ttlmetric(host)
  local ttl = stdnse.get_script_args("firewalk.ttl")
  if ttl then
    return ttl
  end

  -- if no ttl is supplied, the script requires the gateway IP address and the
  -- nmap traceroute resutls to find out the tt value to use
  local gateway = stdnse.get_script_args("firewalk.gateway")
  if not gateway then
    if nmap.verbosity() > 0 then
      nmap.log_write("stdout", "FIREWALK: can't run without one of the script args firewalk.gateway or firewalk.ttl")
      return nil
    end
  end

  if not host.traceroute then
    if not nmap.registry['firewalk'] then
      nmap.registry['firewalk'] = {}
    end
    if nmap.registry['firewalk']['traceroutefail'] then
      return nil
    end
    nmap.registry['firewalk']['traceroutefail'] = true
    if nmap.verbosity() > 0 then
      -- XXX maybe talk about the ttl option?
      nmap.log_write("stdout", "FIREWALK: using the argument `firewalk.gateway' requires unavailable traceroute informations")
    end
    return nil
  end
  if gateway == host.ip then
    if nmap.verbosity() > 0 then
      nmap.log_write("stdout", "FIREWALK: metric and gateway cannot be the same host")
      return nil
    end
  end

  -- look for the ttl value to use according to traceroute results
  for i, hop in pairs(host.traceroute) do
    if hop.ip == gateway then
      return i + 1
    end
  end

  if nmap.verbosity() > 0 then
    nmap.log_write("stdout", "FIREWALK: metric " .. gateway .. " doesn't appear in traceroute")
  end

  return nil
end

--- convert an array of ports into a port ranges string like "x,y-z"
-- @param ports an array of numbers
-- @return a string representing the ports as folded ranges
local function portrange(ports)
  table.sort(ports)
  local numranges = {}

  if #ports == 0 then
    return "(none found)"
  end

  for _, p in ipairs(ports) do
    local stored = false

    -- iterate over the ports list
    for k, range in ipairs(numranges) do
      -- increase an existing range by the left
      if p == range["start"]-1 then
        numranges[k]["start"] = p
        stored = true
      -- increase an existing range by the right
      elseif p == range["stop"]+1 then
        numranges[k]["stop"] = p
        stored = true
      -- port contained in an already existing range (catch doublons)
      elseif p >= range["start"] and p <= range["stop"] then
        stored = true
      end
    end
    -- start a new range
    if not stored then
      local range = {}
      range["start"] = p
      range["stop"] = p
      table.insert(numranges, range)
    end
  end

  -- stringify the ranges
  local strrange = {}
  for i, val in ipairs(numranges) do
    local start = tostring(val["start"])
    local stop = tostring(val["stop"])
    if start == stop then
      table.insert(strrange, start)
    else
      -- contiguous ranges are represented as x-z
      table.insert(strrange, start .. "-" .. stop)
    end
  end
  -- ranges are delimited by `,'
  return stdnse.strjoin(",", strrange)
end

--- pcap check function
-- @return destination ip address, the ip protocol and icmp type
local function check (layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return bin.pack('ACC', ip.ip_bin_dst, ip.ip_p, ip.icmp_type)
end

--- fill a table with the results and dump it to generate the scan report
-- @param tested array of probed ports, one row per protocol
-- @param forwarded array of ports we discovered as forwarded, one row per protocol
-- @return the report string
local function report(tested, forwarded)
  local output = tab.new()

  tab.add(output, 1, "PROTOCOL")
  tab.add(output, 2, "FORWARDED PORTS")
  tab.nextrow(output)

  -- script output: one line per protocol
  for proto in pairs(tested) do
    if #tested[proto] ~= 0 then
      tab.add(output, 1, proto)
      tab.add(output, 2, portrange(forwarded[proto]))
      tab.nextrow(output)
    end
  end

  return tab.dump(output)
end

-- main firewalking logic
action = function(host)
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = packet.toip(host.bin_ip_src)
  local ports = nmap.registry[host.ip]['firewalk_ports']
  local ttl = ttlmetric(host)
  local try = nmap.new_try()
  local fwdports = {} -- results table

  -- abort if unable to bind the scan
  if not ttl then
    return nil
  end

  -- filter for incoming icmp time exceeded replies
  pcap:pcap_open(host.interface, 104, false, "icmp and dst host " .. saddr)

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  pcap:set_timeout(3000)

  -- ports are sorted by protocol
  for proto in pairs(ports) do
    -- cache the currently probed protocol for the whole script
    Protocol = supported_protocols[proto]

    if not Protocol then
      if nmap.verbosity() > 1 then
        nmap.log_write("stdout", "FIREWALK: Unsupported protocol: " .. proto)
      end
      return
    end

    fwdports[proto] = {}

    local pkt = Protocol.genericpkt(host)

    -- iterate over the list of ports for the current protocol
    for _, port in ipairs(ports[proto]) do

      updatepkt(pkt, port, ttl)

      local retry = 0

      -- resend on timeout to increase reliability
      while retry < MAX_RETRIES do

        try(sock:ip_send(pkt.buf))
        stdnse.print_debug(1, "Firewalk: trying port " .. port .. "/" .. proto)

        local status, _, _, rep = pcap:pcap_receive()
        local test = bin.pack('ACC', pkt.ip_bin_src, packet.IPPROTO_ICMP, ICMP_TIME_EXCEEDED);
        while status and test ~= check(rep) do
          status, length, _, layer3 = pcap:pcap_receive();
        end

        if status and checkpkt(rep, pkt) then
          stdnse.print_debug(1, "Firewalk: discovered forwarded port " .. port .. "/" .. proto)
          table.insert(fwdports[proto], port)
          break
        else
          retry = retry + 1
        end

      end -- retry
    end -- port
  end -- proto

  sock:ip_close()
  pcap:pcap_close()

  return "\n" .. report(ports, fwdports)
end

