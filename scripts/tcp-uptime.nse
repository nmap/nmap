local shortport = require "shortport"
local netbios = require "netbios"
local string = require "string"
local stdnse = require "stdnse"

local nmap = require "nmap"
local packet = require "packet"
local os = require "os"
local datetime = require "datetime"

description = [[
Retrieve system boot-time via TCP-options.
This information would be used for detecting NAT, balancing or other information.
]]

---
-- @usage
-- nmap --script tcp-uptime.nse -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE
-- 25/tcp open  smtp
-- | tcp-uptime: 
-- |_  uptime: 21.12.2012 13:37:00
--
-- @xmloutput
-- <table key="uptime">
--   <elem>21.12.2012 13:37:00</elem>
-- </table>
---


author = {"Andrey Zhukov from USSC"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


portrule = function(host, port)
  return host, port
end

tcp_packet = function(host, port)
  local pkt = stdnse.fromhex(
  "4500 0034 0001 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "8002 2000 5ee3 0000 080a 0000 0000 0000" ..
  "0000 0000"
  )
  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  tcp:tcp_set_dport(port.number)
  tcp:tcp_set_sport(math.random(0x401, 0xffff))
  tcp:tcp_set_seq(math.random(1, 0x7fffffff))
  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()

  return tcp
end

get_tcp_options = function(host, port)
  local ifname = nmap.get_interface() or host.interface
  local iface = nmap.get_interface_info(ifname)
  local sock, pcap = nmap.new_dnet(), nmap.new_socket()

  pcap:set_timeout(5000)
  pcap:pcap_open(iface.device, 128, false, ("src host %s and src port %d"):format(host.ip, port.number))
  
  sock:ip_open()
  sock:ip_send(tcp_packet(host, port).buf, host)

  local status, len, layer2, layer3 = pcap:pcap_receive()
  sock:ip_close()
  pcap:close()
  return layer3:sub(20 + 20 + 9, 20 + 20 + 9 + 3)
end

get_uptime = function(options)
  local tcp_timestamp = string.unpack('>I', options) / 100
  return os.date("!*t", os.time() - math.floor(tcp_timestamp))
end

action = function(host, port)
  local output = stdnse.output_table()
  local options = get_tcp_options(host, port)
  if(#options > 0) then
    local uptime = get_uptime(options)
    output.uptime = string.format("%02d.%02d.%04d %02d:%02d:%02d", uptime.day, uptime.month, uptime.year, uptime.hour, uptime.min, uptime.sec)
  else
    output.uptime = "unknown"
  end
  return output
end
