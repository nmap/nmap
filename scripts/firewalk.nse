description = [[
Try to discover firewall rules with an IP TTL expiration technique known
as "firewalking".

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
timeout.  As for UDP scans, this process can be quite slow if lots of ports are
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
-- |_firewalk:  forwarded ports (tcp): 21-80,443
--


-- 08/28/2010
author = "Henri Doreau <henri.doreau[at]gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


require('bin')
require('packet')
require('tab')


local ICMP_TIME_EXCEEDED = 11


-- number of retries for unanswered probes
local MAX_RETRIES = 2


--- ensure that the catched reply is a valid icmp time exceeded and return
-- wether the reply appears to be valid or not
local checkpkt = function(reply, orig)
  local ip = packet.Packet:new(reply, reply:len())

  if ip.ip_p ~= packet.IPPROTO_ICMP or ip.icmp_type ~= ICMP_TIME_EXCEEDED then
    return false
  end

  local is = ip.buf:sub(ip.icmp_offset + 9)
  local ip2 = packet.Packet:new(is, is:len(), true)

  -- Check sent packet against ICMP payload
  if ip2.ip_p ~= packet.IPPROTO_TCP or
    ip2.ip_bin_src ~= orig.ip_bin_src or
    ip2.ip_bin_dst ~= orig.ip_bin_dst or
    ip2.tcp_sport ~= orig.tcp_sport or
    ip2.tcp_dport ~= orig.tcp_dport then

    return false
  end

  return true
end

--- set destination port and ip ttl to a generic tcp packet
-- @param ip the ip object
-- @param dport the layer 4 destination port
-- @param ttl the ip ttl to set
local updatepkt = function(ip, dport, ttl)
  ip:ip_set_ttl(ttl)
  ip:tcp_set_sport(math.random(0x401, 0xffff))
  ip:tcp_set_dport(dport)
  ip:tcp_set_seq(math.random(1, 0x7fffffff))
  ip:tcp_count_checksum(ip.ip_len)
  ip:ip_count_checksum()
end

--- create a generic tcp packet, with ip ttl and destination port set to zero
-- @param host Host object that represents the destination
-- @return the ip packet object
local genericpkt = function(host)
    local pkt = bin.pack("H",
        "4500 002c 55d1 0000 8006 0000 0000 0000" ..
        "0000 0000 0000 0000 0000 0000 0000 0000" ..
        "6002 0c00 0000 0000 0204 05b4"
    )

    local tcp = packet.Packet:new(pkt, pkt:len())

    tcp:ip_set_bin_src(host.bin_ip_src)
    tcp:ip_set_bin_dst(host.bin_ip)

    updatepkt(tcp, 0, 0)

    return tcp
end

--- get the list of ports to probe
-- @param host Host object that represents the targetted host
-- @return list of ports to probe
local getports = function(host)
  local ports = {}
  local port = nil

  repeat
    port = nmap.get_ports(host, port, "tcp", "filtered")
    if port then
      table.insert(ports, port.number)
    end
  until not port

  return ports
end

--- store the firewalk ports into the registry
-- @param host Host object that represents the targetted host
-- @param ports list of ports to firewalk
local setregs = function(host, ports)
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
  local ports = getports(host)
  if #ports < 1 then
    return false
  end
  setregs(host, ports)
  return true
end

--- bind the scan to gateway(ttl) + 1
-- @param host Host object that represents the targetted host
-- @return the value of the ttl to use in our probes (or nil on error)
local ttlmetric = function(host)
  local ttl = stdnse.get_script_args("firewalk.ttl")
  if ttl ~= nil then
    return ttl
  end

  -- if no ttl is supplied, the script requires the gateway IP address and the
  -- nmap traceroute resutls to find out the tt value to use
  local gateway = stdnse.get_script_args("firewalk.gateway")
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
      return i + 2
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
local portrange = function(ports)
  table.sort(ports)
  local numranges = {}
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
local function check (size, layer2, layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return bin.pack('ACC', ip.ip_bin_dst, ip.ip_p, ip.icmp_type)
end

-- main firewalking logic
action = function(host)
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = packet.toip(host.bin_ip_src)
  local ports = nmap.registry[host.ip]['firewalk_ports']
  local ttl = ttlmetric(host)
  local try = nmap.new_try()
  local fwdports = {}

  -- abort if unable to bind the scan
  if not ttl then
    return nil
  end

  -- filter for incoming icmp time exceeded replies
  pcap:pcap_open(host.interface, 104, false, "icmp and dst host " .. saddr)

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  pcap:set_timeout(3000)

  local pkt = genericpkt(host)

  -- iterate over the list of ports
  for _, port in ipairs(ports) do
    updatepkt(pkt, port, ttl)
    local retry = 0

    -- resend on timeout to increase reliability
    while retry < MAX_RETRIES do
      try(sock:ip_send(pkt.buf))

      local status, length, layer2, layer3 = pcap:pcap_receive();
      local test = bin.pack('ACC', pkt.ip_bin_src, packet.IPPROTO_ICMP, ICMP_TIME_EXCEEDED);
      while status and test ~= check(length, layer2, layer3) do
        status, length, layer2, layer3 = pcap:pcap_receive();
      end

      if status then
        if checkpkt(layer3, pkt) then
          stdnse.print_debug(1, "Firewalk: discovered fwd port " .. port)
          table.insert(fwdports, port)
          break
        end
      else
        retry = retry + 1
      end
    end
  end

  sock:ip_close()
  pcap:pcap_close()

  if #fwdports < 1 then
    return "\n no forwarded ports found"
  else
    return "\n forwarded ports (tcp): " .. portrange(fwdports)
  end
end

