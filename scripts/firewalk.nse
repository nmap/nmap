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
-- @args firewalk.max-retries the maximum number of allowed retransmissions
-- @args firewalk.recv-timeout the duration of the packets capture loop (in milliseconds)
-- @args firewalk.probe-timeout validity period of a probe (in milliseconds)
-- @args firewalk.max-active-probes maximum number of parallel active probes
-- @args firewalk.max-probed-ports maximum number of ports to probe per protocol. Set to -1 to scan every filtered ports
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

author = "Henri Doreau"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- TODO
--  o add an option to select gateway(s)/TTL(s) to probe
--  o remove traceroute dependency


require('bin')
require('stdnse')
require('packet')
require('tab')



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



-- probed port states
local PSTATE_UNKNOWN = 0
local PSTATE_SCANNED = 1


-- ICMP constant
local ICMP_TIME_EXCEEDED = 11



--- lookup for TTL of a given gateway in a traceroute results table
-- @param traceroute a host traceroute results table
-- @param gw the IP address of the gateway (as a decimal-dotted string)
-- @return the TTL of the gateway or -1 on error
local function gateway_ttl(traceroute, gw)

  for ttl, hop in ipairs(traceroute) do
    -- chekc hop.ip ~= nil as timedout hops are represented by empty tables
    if hop.ip and hop.ip == gw then
      return ttl
    end
  end

  return -1
end


--=
-- Protocol specific functions are broken down per protocol, in separate tables.
-- This design eases the addition of new protocols
--=

--- TCP related functions
local tcp_funcs = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.tcp_dport

    if port and scanner.ports.tcp[port] then

      stdnse.print_debug("Marking port %d/tcp as forwarded (reply from %s)", ip2.tcp_dport, packet.toip(ip.ip_bin_src))

      -- mark the gateway as forwarding the packet
      scanner.ports.tcp[port].final_ttl = gateway_ttl(scanner.target.traceroute, packet.toip(ip.ip_bin_src))
      scanner.ports.tcp[port].state = PSTATE_SCANNED

      -- remove the related probe
      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "tcp" and probe.portno == ip2.tcp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.print_debug("Invalid reply to port %d/tcp", ip2.tcp_dport)
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

-- UDP related functions
local udp_funcs = {

  --- update the global scan status with a reply
  -- @param scanner the scanner handle
  -- @param ip the ICMP time exceeded error packet
  -- @param ip2 the ICMP payload (our original expired probe)
  update_scan = function(scanner, ip, ip2)

    local port = ip2.udp_dport

    if port and scanner.ports.udp[port] then

      stdnse.print_debug("Marking port %d/udp as forwarded", ip2.udp_dport)

      -- mark the gateway as forwarding the packet
      scanner.ports.udp[port].final_ttl = gateway_ttl(scanner.target.traceroute, packet.toip(ip.ip_bin_src))
      scanner.ports.udp[port].state = PSTATE_SCANNED

      for i, probe in ipairs(scanner.active_probes) do
        if probe.proto == "udp" and probe.portno == ip2.udp_dport then
          table.remove(scanner.active_probes, i)
        end
      end

    else
      stdnse.print_debug("Invalid reply to port %d/udp", ip2.udp_dport)
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

-- list of supported protocols
local supported_protocols = {
  tcp = tcp_funcs,
  udp = udp_funcs,
}

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

    portlist[proto] = {}

    repeat
      port = nmap.get_ports(host, port, proto, state)

      -- do not include administratively prohibited ports
      if port and port.reason == "no-response" then
        local pentry = {
          final_ttl = 0,          -- TTL of the blocking gateway
          state = PSTATE_UNKNOWN, -- initial state: unprobed => unknown
        }

        portlist[proto][port.number] = pentry
        i = i + 1
      end

    until not port or i == MaxProbedPorts
  end

  return portlist

end

--- store the portlist in the register
-- @param host the destination host object
-- @param ports the table of ports to probe
local function setregs(host, ports)

  if not nmap.registry[host.ip] then
    nmap.registry[host.ip] = {}
  end

  nmap.registry[host.ip]['firewalk_ports'] = ports

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
      stdnse.print_debug("Invalid time specification for option: firewalk.recv-timeout (%s)", timespec)
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
      stdnse.print_debug("Invalid time specification for option: firewalk.probe-timeout (%s)", timespec)
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
      stdnse.print_debug("%s not running for lack of privileges.", SCRIPT_NAME)
    end

    return false
  end

  if nmap.address_family() ~= 'inet' then
    stdnse.print_debug("%s is IPv4 compatible only.", SCRIPT_NAME)
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
  local portlist = build_portlist(host)
  local nb_ports = 0

  for _, proto in pairs(portlist) do
    for _ in pairs(proto) do
      nb_ports = nb_ports + 1
    end
  end

  -- nothing to probe: cancel the execution
  if nb_ports < 1 then
    return false
  end

  setregs(host, portlist)

  return true
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
      stdnse.print_debug("%s requires unavailable traceroute informations.", SCRIPT_NAME)
    end

    return nil
  end

  stdnse.print_debug("Using ttl %d", #host.traceroute)
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

--- check whether an incoming IP packet is an ICMP TIME_EXCEEDED packet or not
-- @param src the source IP address
-- @param layer3 the IP incoming datagram
-- @return whether the packet seems to be a valid reply or not
local function check(src, layer3)

  local ip = packet.Packet:new(layer3, layer3:len())
  return ip.ip_bin_dst == src and ip.ip_p == packet.IPPROTO_ICMP and ip.icmp_type == ICMP_TIME_EXCEEDED

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
    {ip = packet.toip(scanner.target.bin_ip_src)}
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
      if port.state == PSTATE_UNKNOWN then
        return false
      end
    end
  end

  -- every ports have been scanned
  return true
end

--- send a probe and update it
-- @param scanner the scanner handle
-- @param probe the probe specifications and related informations
local function send_probe(scanner, probe)

  local try = nmap.new_try(function() scanner.sock:ip_close() end)

  stdnse.print_debug("Sending new probe (%d/%s ttl=%d)", probe.portno, probe.proto, probe.ttl)

  -- craft the raw packet
  local pkt = supported_protocols[probe.proto].getprobe(scanner.target, probe.portno, probe.ttl)

  try(scanner.sock:ip_send(pkt.buf))

  -- update probe informations
  probe.retry = probe.retry + 1
  probe.sent_time = nmap.clock_ms()

end

--- send some new probes
-- @param scanner the scanner handle
local function send_next_probes(scanner)

  -- this prevents sending too much probes at the same time
  while #scanner.active_probes < MaxActiveProbes do

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

--- update global state with an incoming reply
-- @param scanner the scanner handle
-- @param pkt an incoming valid IP packet
local function parse_reply(scanner, pkt)

  local ip = packet.Packet:new(pkt, pkt:len())

  if ip.ip_p ~= packet.IPPROTO_ICMP or ip.icmp_type ~= ICMP_TIME_EXCEEDED then
    return
  end

  local is = ip.buf:sub(ip.icmp_offset + 9)
  local ip2 = packet.Packet:new(is, is:len(), true)

  -- check ICMP payload
  if ip2.ip_bin_src == scanner.target.bin_ip_src and
    ip2.ip_bin_dst == scanner.target.bin_ip then

    -- layer 4 checks
    local proto_func = supported_protocols[proto2str(ip2.ip_p)]
    if proto_func then
      -- mark port as forwarded and discard any related pending probes
      proto_func.update_scan(scanner, ip, ip2)
    else
      stdnse.print_debug("Invalid protocol for reply (%d)", ip2.ip_p)
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

    if status and check(scanner.target.bin_ip_src, l3) then
      parse_reply(scanner, l3)
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
          scanner.ports[probe.proto][probe.portno].state = PSTATE_SCANNED

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
  local saddr = packet.toip(host.bin_ip_src)

  -- scan handle, scanner state is saved in this table
  local scanner = {
    target = host,
    ttl = initial_ttl(host),

    sock = nmap.new_dnet(),
    pcap = nmap.new_socket(),

    ports = nmap.registry[host.ip]['firewalk_ports'],

    sendqueue = {},       -- pending probes
    pending_resends = {}, -- probes needing to be resent
    active_probes = {},   -- probes currently neither replied nor timedout
  }

  if not scanner.ttl then
    return nil
  end

  -- filter for incoming ICMP time exceeded replies
  scanner.pcap:pcap_open(host.interface, 104, false, "icmp and dst host " .. saddr)

  local try = nmap.new_try()

  try(scanner.sock:ip_open())

  generate_initial_probes(scanner)

  while not finished(scanner) do
    send_next_probes(scanner)
    read_replies(scanner)
    update_probe_queues(scanner)
  end

  scanner.sock:ip_close()
  scanner.pcap:pcap_close()

  return report(scanner)
end

