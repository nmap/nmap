local nmap = require "nmap"
local packet = require "packet"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local target = require "target"
local table = require "table"
local math = require "math"
local string = require "string"

description = [[
Discovers routers that are running PIM (Protocol Independent Multicast).

This works by sending a PIM Hello message to the PIM multicast address
224.0.0.13 and listening for Hello messages from other routers.
]]

---
-- @args broadcast-pim-discovery.timeout Time to wait for responses in seconds.
-- Defaults to <code>5s</code>.
--
--@usage
-- nmap --script broadcast-pim-discovery
--
-- nmap --script broadcast-pim-discovery -e eth1
--  --script-args 'broadcast-pim-discovery.timeout=10'
--
--@output
-- Pre-scan script results:
-- | broadcast-pim-discovery:
-- |   172.16.0.12
-- |   172.16.0.31
-- |   172.16.0.44
-- |_  Use the newtargets script-arg to add the results as targets


author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "broadcast"}

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

-- Generates a raw PIM Hello message.
--@return hello Raw PIM Hello message
local helloRaw = function()
  local hello_raw = string.pack(">BB I2",
    0x20, -- Version: 2, Type: Hello (0)
    0x00, -- Reserved
    0x0000) -- Checksum: Calculated later
    -- Options (TLVs)
    .. string.pack(">I2I2 I2", 0x01, 0x02, 0x01) -- Hold time 1 second
    .. string.pack(">I2I2 I4", 0x14, 0x04, math.random(23456)) -- Generation ID: Random
    .. string.pack(">I2I2 I4", 0x13, 0x04, 0x01) -- DR Priority: 1
    .. string.pack(">I2I2 BBI2", 0x15, 0x04, 0x01, 0x00, 0x00) -- State fresh capable: Version = 1, interval = 0, Reserved
  -- Calculate checksum
  hello_raw = hello_raw:sub(1,2) .. string.pack(">I2", packet.in_cksum(hello_raw)) .. hello_raw:sub(5)

  return hello_raw
end

-- Sends a PIM Hello message.
--@param interface Network interface to use.
--@param dstip Destination IP to which send the Hello.
local helloQuery = function(interface, dstip)
  local hello_packet, sock, eth_hdr
  local srcip = interface.address

  local hello_raw = helloRaw()
  local ip_raw = stdnse.fromhex( "45c00040ed780000016718bc0a00c8750a00c86b") .. hello_raw
  hello_packet = packet.Packet:new(ip_raw, ip_raw:len())
  hello_packet:ip_set_bin_src(ipOps.ip_to_str(srcip))
  hello_packet:ip_set_bin_dst(ipOps.ip_to_str(dstip))
  hello_packet:ip_set_len(ip_raw:len()) hello_packet:ip_count_checksum()

  sock = nmap.new_dnet()
  sock:ethernet_open(interface.device)
  -- Ethernet multicast for PIM, our ethernet address and packet type IP
  eth_hdr = "\x01\x00\x5e\x00\x00\x0d" .. interface.mac .. "\x08\x00"
  sock:ethernet_send(eth_hdr .. hello_packet.buf)
  sock:ethernet_close()
end

-- Listens for PIM Hello messages.
--@param interface Network interface to listen on.
--@param timeout Time to listen for a response.
--@param responses table to insert responders' IPs into.
local helloListen = function(interface, timeout, responses)
  local condvar = nmap.condvar(responses)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local p, hello_raw, status, l3data, _

  -- PIM packets that are sent to 224.0.0.13 and not coming from our host
  local filter = 'ip proto 103 and dst host 224.0.0.13 and src host not ' .. interface.address
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      p = packet.Packet:new(l3data, #l3data)
      hello_raw = string.sub(l3data, p.ip_hl*4 + 1)
      -- Check that PIM Type is Hello
      if p and hello_raw:byte(1) == 0x20 then
        table.insert(responses, p.ip_src)
      end
    end
  end
  condvar("signal")
end

--- Returns the network interface used to send packets to the destination host.
--@param destination host to which the interface is used.
--@return interface Network interface used for destination host.
local getInterface = function(destination)
  -- First, create dummy UDP connection to get interface
  local sock = nmap.new_socket()
  local status, err = sock:connect(destination, "12345", "udp")
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
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local responses = {}
  timeout = (timeout or 5) * 1000
  local mcast = "224.0.0.13"

  -- Get the network interface to use
  local interface = nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
  else
    interface = getInterface(mcast)
  end
  if not interface then
    return stdnse.format_output(false, ("Couldn't get interface for %s"):format(mcast))
  end

  stdnse.debug1("will send via %s interface.", interface.shortname)

  -- Launch listener
  stdnse.new_thread(helloListen, interface, timeout, responses)

  -- Send Hello after small sleep so the listener doesn't miss any responses
  stdnse.sleep(0.1)
  helloQuery(interface, mcast)
  local condvar = nmap.condvar(responses)
  condvar("wait")

  if #responses > 0 then
    table.sort(responses)
    if target.ALLOW_NEW_TARGETS then
      for _, response in pairs(responses) do
        target.add(response)
      end
    else
      table.insert(responses,"Use the newtargets script-arg to add the results as targets")
    end
    return stdnse.format_output(true, responses)
  end
end
