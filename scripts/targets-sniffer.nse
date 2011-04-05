-- -*- mode: lua -*-:
-- vim: set filetype=lua :

description = [[
Sniffs the local network for a configurable amount of time and prints
discovered addresses. If <code>newtargets</code> is true, adds the addresses to
the queue to be scanned.

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

author = "Nick Nikolaou <nikolasnikolaou1@gmail.com>"
categories = {"broadcast", "discovery"}
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

require("stdnse")
require("target")
require("nmap")
require("packet")
require("bin")

local interface_info
local all_addresses= {}
local unique_addresses = {}

--Make sure the IP is not a broadcast or the local address
local function check_if_valid(address)
  local broadcast = interface_info.broadcast
  local local_address = interface_info.address

  if address == local_address or address == broadcast or address == "255.255.255.255" then
    return false
  else
    return true end
end

local function get_ip_addresses(layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return packet.toip(ip.ip_bin_src),packet.toip(ip.ip_bin_dst)
end

prerule =  function()
  return true
end


action = function()

  local sock = nmap.new_socket()
  local ip_src,ip_dst
  local packet_counter = 0
  local ip_counter = 0
  local DEFAULT_TIMEOUT_SEC = 10 -- Default timeout value in seconds if the timeout argument is not specified
  local timeoutstr =  stdnse.get_script_args("targets-sniffer.timeout") or tostring(DEFAULT_TIMEOUT_SEC)
  local timeout = (stdnse.parse_timespec(timeoutstr) * 1000)
  local interface = stdnse.get_script_args("targets-sniffer.iface") or nmap.get_interface()
  interface_info = nmap.get_interface_info(interface)

  if interface_info==nil then -- Check if we have the interface information
    stdnse.print_debug(1,"Error: Unable to get interface info. Did you specify the correct interface using 'targets-sniffer.iface=<interface>' or '-e <interface>'?")
    return
  end


  if sock==nil then
    stdnse.print_debug(1,"Error - unable to open socket using interface %s",interface)
    return
  else
    sock:pcap_open(interface, 104, false , "ip")
    stdnse.print_debug(1, "Will sniff for %s seconds on interface %s.", (timeout/1000),interface)

    repeat

      local start_time = nmap.clock_ms() -- Used for script timeout
      sock:set_timeout(timeout)
      local status, _, _, layer3 = sock:pcap_receive()

      if status then

        packet_counter=packet_counter+1
        ip_src,ip_dst = get_ip_addresses(layer3)
        stdnse.print_debug(1,"Got IP addresses %s and %s",ip_src,ip_dst)

        if check_if_valid(ip_src) == true then
          if not unique_addresses[ip_src] then
            unique_addresses[ip_src] = true
            table.insert(all_addresses,ip_src)
          end
        end


        if check_if_valid(ip_dst) == true then
          if not unique_addresses[ip_dst] then
            unique_addresses[ip_dst] = true
            table.insert(all_addresses,ip_dst)
          end
        end

      end
      -- Update timeout
      timeout = timeout - (nmap.clock_ms() - start_time)

    until timeout <= 0

    sock:pcap_close()
  end

  if target.ALLOW_NEW_TARGETS == true then
    for _,v in pairs(all_addresses) do
      target.add(v)
   end
    else
      stdnse.print_debug(1,"Not adding targets to newtargets. If you want to do that use the 'newtargets' script argument.")
  end

  if #all_addresses>0 then
    stdnse.print_debug(1,"Added %s address(es) to newtargets", #all_addresses)
  end

  return string.format("Sniffed %s address(es). \n", #all_addresses) .. stdnse.strjoin("\n",all_addresses)
end
