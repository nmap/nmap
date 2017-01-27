local bin = require "bin"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Tries to discover firewall rules using an IP TTL expiration technique known
as firewalking.

To determine a rule on a given gateway, the scanner sends a probe to a metric
located behind the gateway, with a TTL one higher than the gateway. If the probe
is forwarded by the gateway, then we can expect to receive an ICMP_TIME_EXCEEDED
reply from the gateway next hop router, or eventually the metric itself if it is
directly connected to the gateway. Otherwise, the probe will timeout.

It starts with a TTL equals to the distance to the target. If the probe timeout,
then it is resent with a TTL decreased by one. If we get an ICMP_TIME_EXCEEDED,
then the scan is over for this probe.

Every "no-reply" filtered TCP and UDP ports are probed. As for UDP scans, this
process can be quite slow if lots of ports are blocked by a gateway close to the
scanner.

Scan parameters can be controlled using the <code>firewalk.*</code>
optional arguments.

From an original idea of M. Schiffman and D. Goldsmith, authors of the
firewalk tool.
]]


---
-- @usage
-- nmap --script=firewalk --traceroute <host>
--
-- @usage
-- nmap --script=firewalk --traceroute --script-args=firewalk.max-retries=1 <host>
--
-- @usage
-- nmap --script=firewalk --traceroute --script-args=firewalk.probe-timeout=400ms <host>
--
-- @usage
-- nmap --script=firewalk --traceroute --script-args=firewalk.max-probed-ports=7 <host>
--
--
-- @args firewalk.max-retries the maximum number of allowed retransmissions.
-- @args firewalk.recv-timeout the duration of the packets capture loop (in milliseconds).
-- @args firewalk.probe-timeout validity period of a probe (in milliseconds).
-- @args firewalk.max-active-probes maximum number of parallel active probes.
-- @args firewalk.max-probed-ports maximum number of ports to probe per protocol. Set to -1 to scan every filtered port.
--
--
-- @output
-- | firewalk:
-- | HOP HOST         PROTOCOL  BLOCKED PORTS
-- | 2   192.168.1.1  tcp       21-23,80
-- |                  udp       21-23,80
-- | 6   10.0.1.1     tcp       67-68
-- | 7   10.0.1.254   tcp       25
-- |_                 udp       25
--
--


-- 11/29/2010: initial version
-- 03/28/2011: added IPv4 check
-- 01/02/2012: added IPv6 support

author = "Henri Doreau"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- TODO
--  o add an option to select gateway(s)/TTL(s) to probe
--  o remove traceroute dependency




-----=  scan parameters defaults  =-----

-- number of retries for unanswered probes
local DEFAULT_MAX_RETRIES = 2

-- packets capture loop timeout in milliseconds
local DEFAULT_RECV_TIMEOUT = 20

-- probe life time in milliseconds
local DEFAULT_PROBE_TIMEOUT = 2000

-- max number of simultaneously neither replied nor timed out probes
local DEFAULT_MAX_ACTIVE_PROBES = 20

-- maximum number of probed ports per protocol
local DEFAULT_MAX_PROBED_PORTS = 10

----------------------------------------



-- global scan parameters
local MaxRetries
local RecvTimeout
local ProbeTimeout
local MaxActiveProbes
local MaxProbedPorts

-- cache ports to probe between the hostrule and the action function
local FirewalkPorts


-- ICMP constants
local ICMP_TIME_EXCEEDEDv4 = 11
local ICMP_TIME_EXCEEDEDv6 = 03



-- Layer 4 specific function tables
local proto_vtable = {}

-- Layer 3 specific function tables for the scanner
local Firewalk = {}


--- lookup for TTL of a given gateway in a traceroute results table
-- @param traceroute a host traceroute results table
-- @param gw the IP address of the gateway (as a decimal-dotted string)
-- @return the TTL of the gateway or -1 on error
local function gateway_ttl(traceroute, gw)

  for ttl, hop in ipairs(traceroute) do
    -- check hop.ip ~= nil as timedout hops are represented by empty tables
    if hop.ip and hop.ip == gw then
      return ttl
    end
  end

  return -1
end

--- get the protocol name given its "packet" value
-- @param proto the protocol value (eg. packet.IPPROTO_*)
-- @return the protocol name as a string
local function proto2str(proto)

  if proto == packet.IPPROTO_TCP then
    return "tcp"
  elseif proto == packet.IPPROTO_UDP then
    return "udp"
  end

  return nil
end


--=
-- Protocol specific functions are broken down per protocol, in separate tables.
-- This design eases the addition of new protocols.
--
-- Layer 4 (TCP, UDP) tables are duplicated to distinguish IPv4 and IPv6
-- versions.
--=

--- TCP related functions (IPv4 versions)
local tcp_funcs_v4 = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.tcp_dport

    if port and scanner.ports.tcp[port] then

      stdnse.debug1("Marking port %d/tcp v4 as forwarded (reply from %s)", ip2.tcp_dport, ip.ip_src)

      -- mark the gateway as forwarding the packet
      scanner.ports.tcp[port].final_ttl = gateway_ttl(scanner.target.traceroute, ip.ip_src)
      scanner.ports.tcp[port].scanned = true

      -- remove the related probe
      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "tcp" and probe.portno == ip2.tcp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.debug1("Invalid reply to port %d/tcp", ip2.tcp_dport)
    end
  end,

  --- create a TCP probe packet
  -- @param host Host object that represents the destination
  -- @param dport the TCP destination port
  -- @param ttl the IP time to live
  -- @return the newly crafted IP packet
  getprobe = function(host, dport, ttl)
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

    ip:tcp_set_sport(math.random(0x401, 0xffff))
    ip:tcp_set_dport(dport)
    ip:tcp_set_seq(math.random(1, 0x7fffffff))
    ip:tcp_count_checksum()
    ip:ip_set_ttl(ttl)
    ip:ip_count_checksum()

    return ip
  end,

}

-- UDP related functions (IPv4 versions)
local udp_funcs_v4 = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.udp_dport

    if port and scanner.ports.udp[port] then

      stdnse.debug1("Marking port %d/udp v4 as forwarded", ip2.udp_dport)

      -- mark the gateway as forwarding the packet
      scanner.ports.udp[port].final_ttl = gateway_ttl(scanner.target.traceroute, ip.ip_src)
      scanner.ports.udp[port].scanned = true

      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "udp" and probe.portno == ip2.udp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.debug1("Invalid reply to port %d/udp", ip2.udp_dport)
    end

  end,

  --- create a generic UDP probe packet, with IP ttl and destination port set to zero
  -- @param host Host object that represents the destination
  -- @param dport the UDP destination port
  -- @param ttl the IP time to live
  -- @return the newly crafted IP packet
  getprobe = function(host, dport, ttl)
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

    ip:udp_set_sport(math.random(0x401, 0xffff))
    ip:udp_set_dport(dport)
    ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
    ip:udp_count_checksum()
    ip:ip_set_ttl(ttl)
    ip:ip_count_checksum()

    return ip
  end,
}

--- TCP related functions (IPv6 versions)
local tcp_funcs_v6 = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.tcp_dport

    if port and scanner.ports.tcp[port] then

      stdnse.debug1("Marking port %d/tcp v6 as forwarded (reply from %s)", ip2.tcp_dport, ip.ip_src)

      -- mark the gateway as forwarding the packet
      scanner.ports.tcp[port].final_ttl = gateway_ttl(scanner.target.traceroute, ip.ip_src)
      scanner.ports.tcp[port].scanned = true

      -- remove the related probe
      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "tcp" and probe.portno == ip2.tcp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.debug1("Invalid reply to port %d/tcp", ip2.tcp_dport)
    end
  end,

  --- create a TCP probe packet
  -- @param host Host object that represents the destination
  -- @param dport the TCP destination port
  -- @param ttl the IP time to live
  -- @return the newly crafted IP packet
  getprobe = function(host, dport, ttl)
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0000 0000 0000 0000 6002 0c00 0000 0000 0204 05b4"
    )

    local tcp = packet.Packet:new(pktbin, pktbin:len())
    local ip = packet.Packet:new()

    tcp:tcp_parse(false)

    tcp:tcp_set_sport(math.random(0x401, 0xffff))
    tcp:tcp_set_dport(dport)
    tcp:tcp_set_seq(math.random(1, 0x7fffffff))
    tcp:tcp_count_checksum()
    tcp:ip_count_checksum()

    -- Extract layer 4 part and add it as payload to the IP packet
    local tcp_buf = tcp.buf:sub(tcp.tcp_offset + 1, tcp.buf:len())
    ip:build_ipv6_packet(host.bin_ip_src, host.bin_ip, packet.IPPROTO_TCP, tcp_buf, ttl)

    return ip
  end,

}

-- UDP related functions (IPv6 versions)
local udp_funcs_v6 = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.udp_dport

    if port and scanner.ports.udp[port] then

      stdnse.debug1("Marking port %d/udp v6 as forwarded (reply from %s)", ip2.udp_dport, ip2.ip_src)

      -- mark the gateway as forwarding the packet
      scanner.ports.udp[port].final_ttl = gateway_ttl(scanner.target.traceroute, ip.ip_src)
      scanner.ports.udp[port].scanned = true

      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "udp" and probe.portno == ip2.udp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.debug1("Invalid reply to port %d/udp", ip2.udp_dport)
    end

  end,

  --- create a generic UDP probe packet, with IP ttl and destination port set to zero
  -- @param host Host object that represents the destination
  -- @param dport the UDP destination port
  -- @param ttl the IP time to live
  -- @return the newly crafted IP packet
  getprobe = function(host, dport, ttl)
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0800 0000"
    )

    local udp = packet.Packet:new(pktbin, pktbin:len())
    local ip = packet.Packet:new()

    udp:udp_parse(false)

    udp:udp_set_sport(math.random(0x401, 0xffff))
    udp:udp_set_dport(dport)
    udp:udp_set_length(8)
    udp:udp_count_checksum()
    udp:ip_count_checksum()

    -- Extract layer 4 part and add it as payload to the IP packet
    local udp_buf = udp.buf:sub(udp.udp_offset + 1, udp.buf:len())
    ip:build_ipv6_packet(host.bin_ip_src, host.bin_ip, packet.IPPROTO_UDP, udp_buf, ttl)

    return ip
  end,
}



--=
-- IP-specific functions. The following tables provides scanner functions that
-- depend on the IP version.
--=


-- IPv4 functions
local Firewalk_v4 = {

  --- IPv4 initialization function. Open injection and reception sockets.
  -- @param scanner the scanner handle
  init = function(scanner)
    local saddr = ipOps.str_to_ip(scanner.target.bin_ip_src)

    scanner.sock = nmap.new_dnet()
    scanner.pcap = nmap.new_socket()

    -- filter for incoming ICMP time exceeded replies
    scanner.pcap:pcap_open(scanner.target.interface, 104, false, "icmp and dst host " .. saddr)

    local try = nmap.new_try()
    try(scanner.sock:ip_open())
  end,

  --- IPv4 cleanup function. Close injection and reception sockets.
  -- @param scanner the scanner handle
  shutdown = function(scanner)
    scanner.sock:ip_close()
    scanner.pcap:pcap_close()
  end,

  --- check whether an incoming IP packet is an ICMP TIME_EXCEEDED packet or not
  -- @param src the source IP address
  -- @param layer3 the IP incoming datagram
  -- @return whether the packet seems to be a valid reply or not
  check = function(src, layer3)
    local ip = packet.Packet:new(layer3, layer3:len())
    return ip.ip_bin_dst == src
            and ip.ip_p == packet.IPPROTO_ICMP
            and ip.icmp_type == ICMP_TIME_EXCEEDEDv4
  end,

  --- update global state with an incoming reply
  -- @param scanner the scanner handle
  -- @param pkt an incoming valid IP packet
  parse_reply = function(scanner, pkt)
    local ip = packet.Packet:new(pkt, pkt:len())

    if ip.ip_p ~= packet.IPPROTO_ICMP or ip.icmp_type ~= ICMP_TIME_EXCEEDEDv4 then
      return
    end

    local is = ip.buf:sub(ip.icmp_offset + 9)
    local ip2 = packet.Packet:new(is, is:len(), true)

    -- check ICMP payload
    if ip2.ip_bin_src == scanner.target.bin_ip_src and
      ip2.ip_bin_dst == scanner.target.bin_ip then

      -- layer 4 checks
      local proto_func = proto_vtable[proto2str(ip2.ip_p)]
      if proto_func then
        -- mark port as forwarded and discard any related pending probes
        proto_func.update_scan(scanner, ip, ip2)
      else
        stdnse.debug1("Invalid protocol for reply (%d)", ip2.ip_p)
      end
    end
  end,
}


-- IPv6 functions
local Firewalk_v6 = {

  --- IPv6 initialization function. Open injection and reception sockets.
  -- @param scanner the scanner handle
  init = function(scanner)
    local saddr = ipOps.str_to_ip(scanner.target.bin_ip_src)

    scanner.sock = nmap.new_dnet()
    scanner.pcap = nmap.new_socket()

    -- filter for incoming ICMP time exceeded replies
    scanner.pcap:pcap_open(scanner.target.interface, 1500, false, "icmp6 and dst host " .. saddr)

    local try = nmap.new_try()
    try(scanner.sock:ip_open())
  end,

  --- IPv6 cleanup function. Close injection and reception sockets.
  -- @param scanner the scanner handle
  shutdown = function(scanner)
    scanner.sock:ip_close()
    scanner.pcap:pcap_close()
  end,

  --- check whether an incoming IP packet is an ICMP TIME_EXCEEDED packet or not
  -- @param src the source IP address
  -- @param layer3 the IP incoming datagram
  -- @return whether the packet seems to be a valid reply or not
  check = function(src, layer3)
    local ip = packet.Packet:new(layer3)
    return ip.ip_bin_dst == src
            and ip.ip_p == packet.IPPROTO_ICMPV6
            and ip.icmpv6_type == ICMP_TIME_EXCEEDEDv6
  end,

  --- update global state with an incoming reply
  -- @param scanner the scanner handle
  -- @param pkt an incoming valid IP packet
  parse_reply = function(scanner, pkt)
    local ip = packet.Packet:new(pkt)

    if ip.ip_p ~= packet.IPPROTO_ICMPV6 or ip.icmpv6_type ~= ICMP_TIME_EXCEEDEDv6 then
      return
    end

    local is = ip.buf:sub(ip.icmpv6_offset + 9, ip.buf:len())
    local ip2 = packet.Packet:new(is)

    -- check ICMP payload
    if ip2.ip_bin_src == scanner.target.bin_ip_src and
      ip2.ip_bin_dst == scanner.target.bin_ip then

      -- layer 4 checks
      local proto_func = proto_vtable[proto2str(ip2.ip_p)]
      if proto_func then
        -- mark port as forwarded and discard any related pending probes
        proto_func.update_scan(scanner, ip, ip2)
      else
        stdnse.debug1("Invalid protocol for reply (%d)", ip2.ip_p)
      end
    end
  end,
}

--- Initialize global function tables according to the current address family
local function firewalk_init()
  if nmap.address_family() == "inet" then
    proto_vtable.tcp = tcp_funcs_v4
    proto_vtable.udp = udp_funcs_v4
    Firewalk = Firewalk_v4
  else
    proto_vtable.tcp = tcp_funcs_v6
    proto_vtable.udp = udp_funcs_v6
    Firewalk = Firewalk_v6
  end
end

--- generate list of ports to probe
-- @param host the destination host object
-- @return an array of the ports to probe, sorted per protocol
local function build_portlist(host)
  local portlist = {}
  local combos = {
    {"tcp", "filtered"},
    {"udp", "open|filtered"}
  }

  for _, combo in ipairs(combos) do
    local i = 0
    local port = nil
    local proto = combo[1]
    local state = combo[2]

    repeat
      port = nmap.get_ports(host, port, proto, state)

      -- do not include administratively prohibited ports
      if port and port.reason == "no-response" then
        local pentry = {
          final_ttl = 0,    -- TTL of the blocking gateway
          scanned = false,  -- initial state: unprobed
        }

        portlist[proto] = portlist[proto] or {}

        portlist[proto][port.number] = pentry
        i = i + 1
      end

    until not port or i == MaxProbedPorts
  end

  return portlist

end

--- wrapper for stdnse.parse_timespec() to get specified value in milliseconds
-- @param spec the time specification string (like "10s", "120ms"...)
-- @return the equivalent number of milliseconds or nil on failure
local function parse_timespec_ms(spec)
  local t = stdnse.parse_timespec(spec)
  if t then
    return t * 1000
  else
    return nil
  end
end

--- set scan parameters using user values if specified or defaults otherwise
local function getopts()

  -- assign parameters to scan constants or use defaults

  MaxRetries = tonumber(stdnse.get_script_args("firewalk.max-retries")) or DEFAULT_MAX_RETRIES

  MaxActiveProbes = tonumber(stdnse.get_script_args("firewalk.max-active-probes")) or DEFAULT_MAX_ACTIVE_PROBES

  MaxProbedPorts = tonumber(stdnse.get_script_args("firewalk.max-probed-ports")) or DEFAULT_MAX_PROBED_PORTS


  -- use stdnse time specification parser for ProbeTimeout and RecvTimeout

  local timespec = stdnse.get_script_args("firewalk.recv-timeout")

  if timespec then

    RecvTimeout = parse_timespec_ms(timespec)

    if not RecvTimeout then
      stdnse.debug1("Invalid time specification for option: firewalk.recv-timeout (%s)", timespec)
      return false
    end

  else
    -- no value supplied: use default
    RecvTimeout = DEFAULT_RECV_TIMEOUT
  end


  timespec = stdnse.get_script_args("firewalk.probe-timeout")

  if timespec then

    ProbeTimeout = parse_timespec_ms(timespec)

    if not ProbeTimeout then
      stdnse.debug1("Invalid time specification for option: firewalk.probe-timeout (%s)", timespec)
      return false
    end

  else
    -- no value supplied: use default
    ProbeTimeout = DEFAULT_PROBE_TIMEOUT
  end

  return true

end

--- host rule, check for requirements before to launch the script
hostrule = function(host)
  if not nmap.is_privileged() then
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    if not nmap.registry[SCRIPT_NAME].rootfail then
      stdnse.verbose1("not running for lack of privileges.")
    end
    nmap.registry[SCRIPT_NAME].rootfail = true
    return false
  end

  if not host.interface then
    return false
  end

  -- assign user's values to scan parameters or use defaults
  if not getopts() then
    return false
  end

  -- get the list of ports to probe
  FirewalkPorts = build_portlist(host)

  -- schedule the execution if there are filtered ports to probe
  return (next(FirewalkPorts) ~= nil)

end

--- return the initial TTL to use (the one of the last gateway before the target)
-- @param host the object representing the target with traceroute results available
-- @return the IP TTL of the last gateway before the target
local function initial_ttl(host)

  if not host.traceroute then
    if not nmap.registry['firewalk'] then
      nmap.registry['firewalk'] = {}
    end

    if nmap.registry['firewalk']['traceroutefail'] then
      return nil
    end

    nmap.registry['firewalk']['traceroutefail'] = true

    if nmap.verbosity() > 0 then
      stdnse.debug1("requires unavailable traceroute information.")
    end

    return nil
  end

  stdnse.debug1("Using ttl %d", #host.traceroute)
  return #host.traceroute
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
      if p == range["start"] - 1 then
        numranges[k]["start"] = p
        stored = true

      -- increase an existing range by the right
      elseif p == range["stop"] + 1 then
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

--- return a printable report of the scan
-- @param scanner the scanner handle
-- @return a printable table of scan results
local function report(scanner)
  local entries = 0
  local output = tab.new(4)

  tab.add(output, 1, "HOP")
  tab.add(output, 2, "HOST")
  tab.add(output, 3, "PROTOCOL")
  tab.add(output, 4, "BLOCKED PORTS")
  tab.nextrow(output)

  -- duplicate traceroute results and add localhost at the beginning
  local path = {
    -- XXX 'localhost' might be a better choice?
    {ip = ipOps.str_to_ip(scanner.target.bin_ip_src)}
  }

  for _, v in pairs(scanner.target.traceroute) do
    table.insert(path, v)
  end


  for ttl = 0, #path - 1 do
    local fwdedports = {}

    for proto, portlist in pairs(scanner.ports) do
      fwdedports[proto] = {}

      for portno, port in pairs(portlist) do

        if port.final_ttl == ttl then
          table.insert(fwdedports[proto], portno)
        end
      end
    end


    local nb_fports = 0

    for _, proto in pairs(fwdedports) do
      for _ in pairs(proto) do
        nb_fports = nb_fports + 1
      end
    end

    if nb_fports > 0 then

      entries = entries + 1

      -- the blocking gateway is just after the last forwarding one
      tab.add(output, 1, tostring(ttl))

      -- timedout traceroute hops are represented by empty tables
      if path[ttl + 1].ip then
        tab.add(output, 2, path[ttl + 1].ip)
      else
        tab.add(output, 2, "???")
      end

      for proto, ports in pairs(fwdedports) do
        if #fwdedports[proto] > 0 then
          tab.add(output, 3, proto)
          tab.add(output, 4, portrange(ports))
          tab.nextrow(output)
        end
      end
    end
  end

  if entries > 0 then
    return "\n" .. tab.dump(output)
  else
    return "None found"
  end
end

--- check whether the scan is finished or not
-- @param scanner the scanner handle
-- @return if some port is still in unknown state
local function finished(scanner)

  for proto, ports in pairs(scanner.ports) do

    -- ports are sorted per protocol
    for _, port in pairs(ports) do

      -- if a port is still unprobed => we're not done!
      if not port.scanned then
        return false
      end
    end
  end

  -- every ports have been scanned
  return true
end

--- send a probe and update it
-- @param scanner the scanner handle
-- @param probe the probe specifications and related information
local function send_probe(scanner, probe)

  local try = nmap.new_try(function() scanner.sock:ip_close() end)

  stdnse.debug1("Sending new probe (%d/%s ttl=%d)", probe.portno, probe.proto, probe.ttl)

  -- craft the raw packet
  local pkt = proto_vtable[probe.proto].getprobe(scanner.target, probe.portno, probe.ttl)

  try(scanner.sock:ip_send(pkt.buf, scanner.target))

  -- update probe information
  probe.retry = probe.retry + 1
  probe.sent_time = nmap.clock_ms()

end

--- send some new probes
-- @param scanner the scanner handle
local function send_next_probes(scanner)

  -- this prevents sending too much probes at the same time
  while #scanner.active_probes < MaxActiveProbes do

    local probe
    -- perform resends
    if #scanner.pending_resends > 0 then

      probe = scanner.pending_resends[1]
      table.remove(scanner.pending_resends, 1)
      table.insert(scanner.active_probes, probe)
      send_probe(scanner, probe)

    -- send new probes
    elseif #scanner.sendqueue > 0 then

      probe = scanner.sendqueue[1]
      table.remove(scanner.sendqueue, 1)
      table.insert(scanner.active_probes, probe)
      send_probe(scanner, probe)

    -- nothing else to send right now
    else
      return
    end
  end

end

--- wait for incoming replies
-- @param scanner the scanner handle
local function read_replies(scanner)

  -- capture loop
  local timeout = RecvTimeout
  repeat

    local start = nmap.clock_ms()

    scanner.pcap:set_timeout(timeout)

    local status, _, _, l3, _ = scanner.pcap:pcap_receive()

    if status and Firewalk.check(scanner.target.bin_ip_src, l3) then
      Firewalk.parse_reply(scanner, l3)
    end

    timeout = timeout - (nmap.clock_ms() - start)

  until timeout <= 0 or #scanner.active_probes == 0
end

--- delete timedout probes, update pending probes
-- @param scanner the scanner handle
local function update_probe_queues(scanner)

  local now = nmap.clock_ms()

  -- remove timedout probes
  for i, probe in ipairs(scanner.active_probes) do

    if (now - probe.sent_time) >= ProbeTimeout then

      table.remove(scanner.active_probes, i)

      if probe.retry < MaxRetries then
        table.insert(scanner.pending_resends, probe)
      else

        -- decrease ttl, reset retries counter and put probes in send queue
        if probe.ttl > 1 then

          probe.ttl = probe.ttl - 1
          probe.retry = 0
          table.insert(scanner.sendqueue, probe)

        else

          -- set final_ttl to zero (=> probe might be blocked by localhost)
          scanner.ports[probe.proto][probe.portno].final_ttl = 0
          scanner.ports[probe.proto][probe.portno].scanned = true

        end
      end
    end
  end
end

--- fills the send queue with initial probes
-- @param scanner the scanner handle
local function generate_initial_probes(scanner)

  for proto, ports in pairs(scanner.ports) do

    for portno in pairs(ports) do

      -- simply store probe parameters and craft packet at send time
      local probe = {
        ttl = scanner.ttl,  -- initial ttl value
        proto = proto,      -- layer 4 protocol (string)
        portno = portno,    -- layer 4 port number
        retry = 0,          -- retries counter
        sent_time = 0       -- last sending time
      }

      table.insert(scanner.sendqueue, probe)

    end
  end
end

--- firewalk entry point
action = function(host)

  firewalk_init() -- global script initialization process

  -- scan handle, scanner state is saved in this table
  local scanner = {
    target = host,
    ttl = initial_ttl(host),

    ports = FirewalkPorts,

    sendqueue = {},       -- pending probes
    pending_resends = {}, -- probes needing to be resent
    active_probes = {},   -- probes currently neither replied nor timedout
  }

  if not scanner.ttl then
    return nil
  end

  Firewalk.init(scanner)

  generate_initial_probes(scanner)

  while not finished(scanner) do
    send_next_probes(scanner)
    read_replies(scanner)
    update_probe_queues(scanner)
  end

  Firewalk.shutdown(scanner)

  return report(scanner)
end

