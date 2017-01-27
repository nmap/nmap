local ipOps = require "ipOps"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

-- -*- mode: lua -*-:
-- vim: set filetype=lua :

description = [[
Sniffs the local network for a configurable amount of time (10 seconds
by default) and prints discovered addresses. If the
<code>newtargets</code> script argument is set, discovered addresses
are added to the scan queue.

Requires root privileges. Either the <code>targets-sniffer.iface</code> script
argument or <code>-e</code> Nmap option to define which interface to use.
]]

---
-- @usage
-- nmap -sL --script=targets-sniffer --script-args=newtargets,targets-sniffer.timeout=5s,targets-sniffer.iface=eth0
-- @args targets-sniffer.timeout  The amount of time to listen for packets. Default <code>10s</code>.
-- @args targets-sniffer.iface  The interface to use for sniffing.
-- @args newtargets If true, add discovered targets to the scan queue.
-- @output
-- Pre-scan script results:
-- | targets-sniffer:
-- | 192.168.0.1
-- | 192.168.0.3
-- | 192.168.0.35
-- |_192.168.0.100


-- Thanks to everyone for the feedback and especially Henri Doreau for his detailed feedback and suggestions

author = "Nick Nikolaou"
categories = {"broadcast", "discovery", "safe"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"


local interface_info
local all_addresses= {}
local unique_addresses = {}

--Make sure the IP is not a broadcast or the local address
local function check_if_valid(address)
  local broadcast = interface_info.broadcast
  local local_address = interface_info.address

  if address == local_address
    or address == broadcast or address == "255.255.255.255"
    or address:match('^ff') --IPv6 Multicast addrs
    then
    return false
  else
    return true end
end

-- Returns an array of address strings.
local function get_ip_addresses(layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return { ipOps.str_to_ip(ip.ip_bin_src), ipOps.str_to_ip(ip.ip_bin_dst) }
end

prerule =  function()
  return nmap.is_privileged() and
    (stdnse.get_script_args("targets-sniffer.iface") or nmap.get_interface())
end


action = function()

  local sock = nmap.new_socket()
  local packet_counter = 0
  local ip_counter = 0
  local timeout = stdnse.parse_timespec(stdnse.get_script_args("targets-sniffer.timeout"))
  timeout = (timeout or 10) * 1000
  local interface = stdnse.get_script_args("targets-sniffer.iface") or nmap.get_interface()
  interface_info = nmap.get_interface_info(interface)

  if interface_info==nil then -- Check if we have the interface information
    stdnse.debug1("Error: Unable to get interface info. Did you specify the correct interface using 'targets-sniffer.iface=<interface>' or '-e <interface>'?")
    return
  end


  if sock==nil then
    stdnse.debug1("Error - unable to open socket using interface %s",interface)
    return
  else
    sock:pcap_open(interface, 104, true, "ip or ip6")
    stdnse.debug1("Will sniff for %s seconds on interface %s.", (timeout/1000),interface)

    repeat

      local start_time = nmap.clock_ms() -- Used for script timeout
      sock:set_timeout(timeout)
      local status, _, _, layer3 = sock:pcap_receive()

      if status then
        local addresses

        packet_counter=packet_counter+1
        addresses = get_ip_addresses(layer3)
        stdnse.debug1("Got IP addresses %s", stdnse.strjoin(" ", addresses))

        for _, addr in ipairs(addresses) do
          if check_if_valid(addr) == true then
            if not unique_addresses[addr] then
              unique_addresses[addr] = true
              table.insert(all_addresses, addr)
            end
          end
        end

      end
      -- Update timeout
      timeout = timeout - (nmap.clock_ms() - start_time)

    until timeout <= 0

    sock:pcap_close()
  end

  if target.ALLOW_NEW_TARGETS == true then
    if nmap.address_family() == 'inet6' then
      for _,v in pairs(all_addresses) do
        if v:match(':') then
          target.add(v)
        end
      end
    else
      for _,v in pairs(all_addresses) do
        if not v:match(':') then
          target.add(v)
        end
      end
    end
  else
    stdnse.debug1("Not adding targets to newtargets. If you want to do that use the 'newtargets' script argument.")
  end

  if #all_addresses>0 then
    stdnse.debug1("Added %s address(es) to newtargets", #all_addresses)
  end

  return string.format("Sniffed %s address(es). \n", #all_addresses) .. stdnse.strjoin("\n",all_addresses)
end
