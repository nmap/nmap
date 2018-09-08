local nmap = require "nmap"
local packet = require "packet"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local table = require "table"
local math = require "math"
local string = require "string"

description = [[
Queries for the multicast path from a source to a destination host.

This works by sending an IGMP Traceroute Query and listening for IGMP
Traceroute responses. The Traceroute Query is sent to the first hop and
contains information about source, destination and multicast group addresses.
First hop defaults to the multicast All routers address. The default multicast
group address is 0.0.0.0 and the default destination is our own host address. A
source address must be provided. The responses are parsed to get interesting
information about interface addresses, used protocols and error codes.

This is similar to the mtrace utility provided in Cisco IOS.
]]

---
--@args mtrace.fromip Source address from which to traceroute.
--
--@args mtrace.toip Destination address to which to traceroute.
-- Defaults to our host address.
--
--@args mtrace.group Multicast group address for the traceroute.
-- Defaults to <code>0.0.0.0</code> which represents all group addresses.
--
--@args mtrace.firsthop Host to which the query is sent. If not set, the
-- query will be sent to <code>224.0.0.2</code>.
--
--@args mtrace.timeout Time to wait for responses.
-- Defaults to <code>7s</code>.
--
--@usage
-- nmap --script mtrace --script-args 'mtrace.fromip=172.16.45.4'
--
--@output
-- Pre-scan script results:
-- | mtrace:
-- |   Group 0.0.0.0 from 172.16.45.4 to 172.16.0.1
-- |   Source: 172.16.45.4
-- |     In address: 172.16.34.3
-- |       Out address: 172.16.0.3
-- |       Protocol: PIM
-- |     In address: 172.16.45.4
-- |       Out address: 172.16.34.4
-- |       Protocol: PIM
-- |   Source: 172.16.45.4
-- |     In address: 172.16.13.1
-- |       Out address: 172.16.0.2
-- |       Protocol: PIM / Static
-- |     In address: 172.16.34.3
-- |       Out address: 172.16.13.3
-- |       Protocol: PIM
-- |     In address: 172.16.45.4
-- |       Out address: 172.16.34.4
-- |_      Protocol: PIM

author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "broadcast"}

-- From: https://tools.ietf.org/id/draft-ietf-idmr-traceroute-ipm-07.txt
PROTO = {
  [0x01] = "DVMRP",
  [0x02] = "MOSPF",
  [0x03] = "PIM",
  [0x04] = "CBT",
  [0x05] = "PIM / Special table",
  [0x06] = "PIM / Static",
  [0x07] = "DVMRP / Static",
  [0x08] = "PIM / MBGP",
  [0x09] = "CBT / Special table",
  [0x10] = "CBT / Static",
  [0x11] = "PIM / state created by Assert processing",
}

FWD_CODE = {
  [0x00] = "NO_ERROR",
  [0x01] = "WRONG_IF",
  [0x02] = "PRUNE_SENT",
  [0x03] = "PRUNE_RCVD",
  [0x04] = "SCOPED",
  [0x05] = "NO_ROUTE",
  [0x06] = "WRONG_LAST_HOP",
  [0x07] = "NOT_FORWARDING",
  [0x08] = "REACHED_RP",
  [0x09] = "RPF_IF",
  [0x0A] = "NO_MULTICAST",
  [0x0B] = "INFO_HIDDEN",
  [0x81] = "NO_SPACE",
  [0x82] = "OLD_ROUTER",
  [0x83] = "ADMIN_PROHIB",
}

prerule = function()
  if nmap.address_family() ~= 'inet' then
    stdnse.verbose1("is IPv4 only.")
    return false
  end
  if not nmap.is_privileged() then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end
  return true
end

--- Generates a raw IGMP Traceroute Query.
--@param fromip Source address.
--@param toip Destination address.
--@param group Multicast group address.
--@param receiver Receiver of the response.
--@return data Raw Traceroute Query.
local traceRaw = function(fromip, toip, group, receiver)
  local data = string.pack(">BBI2 I4 I4 I4 I4 BBI2",
    0x1f, -- Type: Traceroute Query
    0x20, -- Hops: 32
    0x0000, -- Checksum: To be set later
    ipOps.todword(group), -- Multicast group
    ipOps.todword(fromip), -- Source
    ipOps.todword(toip), -- Destination
    ipOps.todword(receiver), -- Receiver
    0x40, -- TTL
    0x00, math.random(123456) -- Query ID
    )

  -- We calculate checksum
  data = data:sub(1,2) .. string.pack(">I2", packet.in_cksum(data)) .. data:sub(5)
  return data
end

--- Sends a raw IGMP Traceroute Query.
--@param interface Network interface to send through.
--@param destination Target host to which the packet is sent.
--@param trace_raw Traceroute raw Query.
local traceSend = function(interface, destination, trace_raw)
  local ip_raw = stdnse.fromhex( "45c00040ed780000400218bc0a00c8750a00c86b") .. trace_raw
  local trace_packet = packet.Packet:new(ip_raw, ip_raw:len())
  trace_packet:ip_set_bin_src(ipOps.ip_to_str(interface.address))
  trace_packet:ip_set_bin_dst(ipOps.ip_to_str(destination))
  trace_packet:ip_set_len(#trace_packet.buf)
  trace_packet:ip_count_checksum()

  if destination == "224.0.0.2" then
    -- Doesn't affect results as it is ignored but most routers, but RFC
    -- 3171 should be respected.
    trace_packet:ip_set_ttl(1)
  end
  trace_packet:ip_count_checksum()

  local sock = nmap.new_dnet()
  if destination == "224.0.0.2" then
    sock:ethernet_open(interface.device)
    -- Ethernet IPv4 multicast, our ethernet address and packet type IP
    local eth_hdr = "\x01\x00\x5e\x00\x00\x02" .. interface.mac .. "\x08\x00"
    sock:ethernet_send(eth_hdr .. trace_packet.buf)
    sock:ethernet_close()
  else
    sock:ip_open()
    sock:ip_send(trace_packet.buf, destination)
    sock:ip_close()
  end
end

--- Parses an IGMP Traceroute Response and returns it in structured form.
--@param data Raw Traceroute Response.
--@return response Structured Traceroute Response.
local traceParse = function(data)
  local index
  local response = {}

  -- first byte should be IGMP type == 0x1e (Traceroute Response)
  if data:byte(1) ~= 0x1e then return end

  -- Hops
  response.hops,
  -- Checksum
  response.checksum,
  -- Group
  response.group,
  -- Source address
  response.source,
  -- Destination address
  response.destination,
  -- Response address
  response.response,
  -- Response TTL
  response.ttl,
  -- Query ID
  response.qid, index = string.unpack(">B I2 I4 I4 I4 I4 B I3", data, 2)

  response.group = ipOps.fromdword(response.group)
  response.source = ipOps.fromdword(response.source)
  response.receiver = ipOps.fromdword(response.destination)
  response.response = ipOps.fromdword(response.response)

  local block
  response.blocks = {}
  -- Now, parse data blocks
  while true do
    -- To end parsing and not get stuck in infinite loops.
    if index >= #data then
      break
    elseif #data - index < 31 then
      stdnse.verbose1("malformed traceroute response.")
      return
    end

    block = {}
    -- Query Arrival
    block.query,
    -- In itf address
    block.inaddr,
    -- Out itf address
    block.outaddr,
    -- Previous rtr address
    block.prevaddr,
    -- In packets
    block.inpkts,
    -- Out packets
    block.outpkts,
    -- S,G pkt count
    block.sgpkt,
    -- Protocol
    block.proto,
    -- Forward TTL
    block.fwdttl,
    -- Options
    block.options,
    -- Forwarding Code
    block.code, index = string.unpack(">I4 I4 I4 I4 I4 I4 I4 BBBB", data, index)

    block.inaddr = ipOps.fromdword(block.inaddr)
    block.outaddr = ipOps.fromdword(block.outaddr)
    block.prevaddr = ipOps.fromdword(block.prevaddr)

    table.insert(response.blocks, block)
  end
  return response
end

-- Listens for IGMP Traceroute responses
--@param interface Network interface to listen on.
--@param timeout Amount of time to listen for in seconds.
--@param responses table to insert responses into.
local traceListener = function(interface, timeout, responses)
  local condvar = nmap.condvar(responses)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local p, trace_raw, status, l3data, response, _

  -- IGMP packets that are sent to our host
  local filter = 'ip proto 2 and dst host ' .. interface.address
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      p = packet.Packet:new(l3data, #l3data)
      trace_raw = string.sub(l3data, p.ip_hl*4 + 1)
      if p then
        -- Check that IGMP Type == 0x1e (Traceroute Response)
        if trace_raw:byte(1) == 0x1e then
          response = traceParse(trace_raw)
          if response then
            response.srcip = p.ip_src
            table.insert(responses, response)
          end
        end
      end
    end
  end
  condvar("signal")
end

-- Returns the network interface used to send packets to a target host.
--@param target host to which the interface is used.
--@return interface Network interface used for target host.
local getInterface = function(target)
  -- First, create dummy UDP connection to get interface
  local sock = nmap.new_socket()
  local status, err = sock:connect(target, "12345", "udp")
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  local status, address, _, _, _ = sock:get_info()
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  for _, interface in pairs(nmap.list_interfaces()) do
    if interface.address == address then
      return interface
    end
  end
end


action = function()
  local fromip = stdnse.get_script_args(SCRIPT_NAME .. ".fromip")
  local toip = stdnse.get_script_args(SCRIPT_NAME .. ".toip")
  local group = stdnse.get_script_args(SCRIPT_NAME .. ".group") or "0.0.0.0"
  local firsthop = stdnse.get_script_args(SCRIPT_NAME .. ".firsthop") or "224.0.0.2"
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local responses = {}
  timeout = (timeout or 7) * 1000

  -- Source address from which to traceroute
  if not fromip then
    stdnse.verbose1("A source IP must be provided through fromip argument.")
    return
  end

  -- Get network interface to use
  local interface = nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
  else
    interface = getInterface(firsthop)
  end
  if not interface then
    return stdnse.format_output(false, ("Couldn't get interface for %s"):format(firsthop))
  end

  -- Destination defaults to our own host
  toip = toip or interface.address

  stdnse.debug1("Traceroute group %s from %s to %s.", group, fromip, toip)
  stdnse.debug1("will send to %s via %s interface.", firsthop, interface.shortname)

  -- Thread that listens for responses
  stdnse.new_thread(traceListener, interface, timeout, responses)

  -- Send request after small wait to let Listener start
  stdnse.sleep(0.1)
  local trace_raw = traceRaw(fromip, toip, group, interface.address)
  traceSend(interface, firsthop, trace_raw)

  local condvar = nmap.condvar(responses)
  condvar("wait")
  if #responses > 0 then
    local outresp
    local output, outblock = {}
    table.insert(output, ("Group %s from %s to %s"):format(group, fromip, toip))
    for _, response in pairs(responses) do
      outresp = {}
      outresp.name = "Source: " .. response.srcip
      for _, block in pairs(response.blocks) do
        outblock = {}
        outblock.name = "In address: " .. block.inaddr
        table.insert(outblock, "Out address: " .. block.outaddr)
        -- Protocol
        if PROTO[block.proto] then
          table.insert(outblock, "Protocol: " .. PROTO[block.proto])
        else
          table.insert(outblock, "Protocol: Unknown")
        end
        -- Error Code, we ignore NO_ERROR which is the normal case.
        if FWD_CODE[block.code] and block.code ~= 0x00 then
          table.insert(outblock, "Error code: " .. FWD_CODE[block.code])
        elseif block.code ~= 0x00 then
          table.insert(outblock, "Error code: Unknown")
        end
        table.insert(outresp, outblock)
      end
      table.insert(output, outresp)
    end
    return stdnse.format_output(true, output)
  end
end
