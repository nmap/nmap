local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Classifies a host's IP ID sequence (test for susceptibility to idle
scan).

Sends six probes to obtain IP IDs from the target and classifies them
similarly to Nmap's method.  This is useful for finding suitable zombies
for Nmap's idle scan (<code>-sI</code>) as Nmap itself doesn't provide a way to scan
for these hosts.
]]

---
-- @usage
-- nmap --script ipidseq [--script-args probeport=port] target
-- @args probeport Set destination port to probe
-- @output
-- Host script results:
-- |_ipidseq: Incremental! [used port 80]

-- I also implemented this in Metasploit as auxiliary/scanner/ip/ipidseq, but
-- this NSE script was actually written first (unfortunately it only worked
-- with vanilla Nmap using dnet ethernet sending.. ugh)
--
-- Originally written 05/24/2008; revived 01/24/2010

author = "Kris Katterjohn"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


local NUMPROBES = 6

local ipidseqport

--- Updates a TCP Packet object
-- @param tcp The TCP object
local updatepkt = function(tcp)
  tcp:tcp_set_sport(math.random(0x401, 0xffff))
  tcp:tcp_set_seq(math.random(1, 0x7fffffff))
  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
end

--- Create a TCP Packet object
-- @param host Host object
-- @param port Port number
-- @return TCP Packet object
local genericpkt = function(host, port)
  local pkt = stdnse.fromhex(
  "4500 002c 55d1 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  tcp:tcp_set_dport(port)
  return tcp
end

--- Classifies a series of IP ID numbers like get_ipid_sequence() in osscan2.cc
-- @param ipids Table of IP IDs
local ipidseqclass = function(ipids)
  local diffs = {}
  local allzeros = true
  local allsame = true
  local mul256 = true
  local inc = true

  if #ipids < 2 then
    return "Unknown"
  end

  local i = 2

  while i <= #ipids do
    if ipids[i-1] ~= 0 or ipids[i] ~= 0 then
      allzeros = false
    end

    if ipids[i-1] <= ipids[i] then
      diffs[i-1] = ipids[i] - ipids[i-1]
    else
      diffs[i-1] = ipids[i] - ipids[i-1] + 65536
    end

    if #ipids > 2 and diffs[i-1] > 20000 then
      return "Randomized"
    end

    i = i + 1
  end

  if allzeros then
    return "All zeros"
  end

  i = 1

  while i <= #diffs do
    if diffs[i] ~= 0 then
      allsame = false
    end

    if (diffs[i] > 1000) and ((diffs[i] % 256) ~= 0 or
      ((diffs[i] % 256) == 0 and diffs[i] > 25600)) then
      return "Random Positive Increments"
    end

    if diffs[i] > 5120 or (diffs[i] % 256) ~= 0 then
      mul256 = false
    end

    if diffs[i] >= 10 then
      inc = false
    end

    i = i + 1
  end

  if allsame then
    return "Constant"
  end

  if mul256 then
    return "Broken incremental!"
  end

  if inc then
    return "Incremental!"
  end

  return "Unknown"
end

--- Determines what port to probe
-- @param host Host object
local getport = function(host)
  for _, k in ipairs({"ipidseq.probeport", "probeport"}) do
    if nmap.registry.args[k] then
      return tonumber(nmap.registry.args[k])
    end
  end

  --local states = { "open", "closed", "unfiltered", "open|filtered", "closed|filtered" }
  local states = { "open", "closed" }
  local port = nil

  for _, s in ipairs(states) do
    port = nmap.get_ports(host, nil, "tcp", s)
    if port then
      break
    end
  end

  if not port then
    return nil
  end

  return port.number
end

hostrule = function(host)
  if not nmap.is_privileged() then
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    if not nmap.registry[SCRIPT_NAME].rootfail then
      stdnse.verbose1("not running for lack of privileges.")
    end
    nmap.registry[SCRIPT_NAME].rootfail = true
    return nil
  end

  if nmap.address_family() ~= 'inet' then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end
  if not host.interface then
    return false
  end
  ipidseqport = getport(host)
  return (ipidseqport ~= nil)
end

action = function(host)
  local ipids = {}
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = ipOps.str_to_ip(host.bin_ip_src)
  local daddr = ipOps.str_to_ip(host.bin_ip)
  local try = nmap.new_try()

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  pcap:pcap_open(host.interface, 104, false, "tcp and dst host " .. saddr .. " and src host " .. daddr .. " and src port " .. ipidseqport)

  pcap:set_timeout(host.times.timeout * 1000)

  local sndpkt = genericpkt(host, ipidseqport)

  for _ = 1, NUMPROBES do
    updatepkt(sndpkt)
    try(sock:ip_send(sndpkt.buf, host))
    local recvpkt
    repeat
      recvpkt = nil
      local status, _, _, recvdata = pcap:pcap_receive()
      if not status then break end
      recvpkt = packet.Packet:new(recvdata, #recvdata)
    until recvpkt and recvpkt.tcp_dport == sndpkt.tcp_sport
    if not recvpkt then break end
    stdnse.debug2("Received IP ID %d (0x%x)", recvpkt.ip_id, recvpkt.ip_id)
    table.insert(ipids, recvpkt.ip_id)
  end

  pcap:close()
  sock:ip_close()

  local output = ipidseqclass(ipids)

  if nmap.debugging() > 0 then
    output = output .. " [used port " .. ipidseqport .. "]"
  end

  return output
end

