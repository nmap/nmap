local coroutine = require "coroutine"
local dhcp = require "dhcp"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local outlib = require "outlib"
local packet = require "packet"
local rand = require "rand"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends a DHCP request to the broadcast address (255.255.255.255) and reports
the results. By default, the script uses a static MAC address
(DE:AD:CO:DE:CA:FE) in order to prevent IP pool exhaustion.

The script reads the response using pcap by opening a listening pcap socket
on all available ethernet interfaces that are reported up. If no response
has been received before the timeout has been reached (default 10 seconds)
the script will abort execution.

The script needs to be run as a privileged user, typically root.
]]

---
-- @see broadcast-dhcp6-discover.nse
-- @see dhcp-discover.nse
--
-- @usage
-- sudo nmap --script broadcast-dhcp-discover
--
-- @output
-- | broadcast-dhcp-discover:
-- |   Response 1 of 1:
-- |     Interface: wlp1s0
-- |     IP Offered: 192.168.1.114
-- |     DHCP Message Type: DHCPOFFER
-- |     Server Identifier: 192.168.1.1
-- |     IP Address Lease Time: 1 day, 0:00:00
-- |     Subnet Mask: 255.255.255.0
-- |     Router: 192.168.1.1
-- |     Domain Name Server: 192.168.1.1
-- |_    Domain Name: localdomain
--
-- @xmloutput
-- <table key="Response 1 of 1:">
--   <elem key="Interface">wlp1s0</elem>
--   <elem key="IP Offered">192.168.1.114</elem>
--   <elem key="DHCP Message Type">DHCPOFFER</elem>
--   <elem key="Server Identifier">192.168.1.1</elem>
--   <elem key="IP Address Lease Time">1 day, 0:00:00</elem>
--   <elem key="Subnet Mask">255.255.255.0</elem>
--   <elem key="Router">192.168.1.1</elem>
--   <elem key="Domain Name Server">192.168.1.1</elem>
--   <elem key="Domain Name">localdomain</elem>
-- </table>
--
-- @args broadcast-dhcp-discover.mac  Set to <code>random</code> or a specific
--                client MAC address in the DHCP request. "DE:AD:C0:DE:CA:FE"
--                is used by default. Setting it to <code>random</code> will
--                possibly cause the DHCP server to reserve a new IP address
--                each time.
-- @args broadcast-dhcp-discover.clientid Client identifier to use in DHCP
--         option 61. The value is a string, while hardware type 0, appropriate
--         for FQDNs, is assumed. Example: clientid=kurtz is equivalent to
--         specifying clientid-hex=00:6b:75:72:74:7a (see below).
-- @args broadcast-dhcp-discover.clientid-hex Client identifier to use in DHCP
--         option 61. The value is a hexadecimal string, where the first octet
--         is the hardware type.
-- @args broadcast-dhcp-discover.timeout time in seconds to wait for a response
--       (default: 10s)
--

-- Created 04/22/2022 - v0.3 - updated by nnposter
--   o Implemented script arguments "clientid" and "clientid-hex" to allow
--     passing a specific client identifier (option 61)
--
-- Created 01/14/2020 - v0.2 - updated by nnposter
--   o Implemented script argument "mac" to force a specific MAC address
--
-- Created 07/14/2011 - v0.1 - created by Patrik Karlsson

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}



prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end

  if nmap.address_family() ~= 'inet' then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end
  return true
end

-- Gets a list of available interfaces based on link and up filters
--
-- @param link string containing the link type to filter
-- @param up string containing the interface status to filter
-- @return result table containing the matching interfaces
local function getInterfaces(link, up)
  if( not(nmap.list_interfaces) ) then return end
  local interfaces, err = nmap.list_interfaces()
  local result
  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
      if ( iface.link == link and iface.up == up ) then
        result = result or {}
        result[iface.device] = true
      end
    end
  end
  return result
end

-- Listens for an incoming dhcp response
--
-- @param iface string with the name of the interface to listen to
-- @param macaddr client hardware address
-- @param options DHCP options to include in the request
-- @param timeout number of ms to wait for a response
-- @param xid the DHCP transaction id
-- @param result a table to which the result is written
local function dhcp_listener(sock, iface, macaddr, options, timeout, xid, result)
  local condvar = nmap.condvar(result)
  local srcip = ipOps.ip_to_str("0.0.0.0")
  local dstip = ipOps.ip_to_str("255.255.255.255")

  -- Build DHCP request
  local status, pkt = dhcp.dhcp_build(
    dhcp.request_types.DHCPDISCOVER,
    srcip,
    macaddr,
    options,
    nil, -- request options
    {flags=0x8000}, -- override: broadcast
    nil, -- lease time
    xid)
  if not status then
    stdnse.debug1("Failed to build packet for %s: %s", iface, pkt)
    condvar "signal"
    return
  end

  -- Add UDP header
  local udplen = #pkt + 8
  local tmp = string.pack(">c4c4 xBI2 I2I2I2xx",
    srcip, dstip,
    packet.IPPROTO_UDP, udplen,
    68, 67, udplen) .. pkt
  pkt = string.pack(">I2 I2 I2 I2", 68, 67, udplen, packet.in_cksum(tmp)) .. pkt

  -- Create a frame and add the IP header
  local frame = packet.Frame:new()
  frame:build_ip_packet(srcip, dstip, pkt, nil, --dsf
    string.unpack(">I2", xid, 3), -- IPID, use 16 lsb of xid
    nil, nil, nil, -- flags, offset, ttl
    packet.IPPROTO_UDP)

  -- Add the Ethernet header
  frame:build_ether_frame(
    "\xff\xff\xff\xff\xff\xff",
    nmap.get_interface_info(iface).mac, -- can't use macaddr or we won't see response
    packet.ETHER_TYPE_IPV4)

  local dnet = nmap.new_dnet()
  dnet:ethernet_open(iface)
  local status, err = dnet:ethernet_send(frame.frame_buf)
  dnet:ethernet_close()
  if not status then
    stdnse.debug1("Failed to send frame for %s: %s", iface, err)
    condvar "signal"
    return
  end

  local start_time = nmap.clock_ms()
  local now = start_time
  while( now - start_time < timeout ) do
    sock:set_timeout(timeout - (now - start_time))
    local status, _, _, data = sock:pcap_receive()

    if ( status ) then
      local p = packet.Packet:new( data, #data )
      if ( p and p.udp_dport ) then
        local data = data:sub(p.udp_offset + 9)
        local status, response = dhcp.dhcp_parse(data, xid)
        if ( status ) then
          response.iface = iface
          table.insert( result, response )
        end
      end
    end
    now = nmap.clock_ms()
  end
  sock:close()
  condvar "signal"
end

local function fail (err) return stdnse.format_output(false, err) end

action = function()

  local timeout = stdnse.parse_timespec(stdnse.get_script_args("broadcast-dhcp-discover.timeout"))
  timeout = (timeout or 10) * 1000

  local options = {}

  local macaddr = (stdnse.get_script_args(SCRIPT_NAME .. ".mac") or "DE:AD:C0:DE:CA:FE"):lower()
  if macaddr:find("^ra?nd") then
    macaddr = rand.random_string(6)
  else
    macaddr = macaddr:gsub(":", "")
    if not (#macaddr == 12 and macaddr:find("^%x+$")) then
      return stdnse.format_output(false, "Invalid MAC address")
    end
    macaddr = stdnse.fromhex(macaddr)
  end

  local clientid = stdnse.get_script_args(SCRIPT_NAME .. ".clientid")
  if clientid then
    clientid = "\x00" .. clientid  -- hardware type 0 presumed
  else
    clientid = stdnse.get_script_args(SCRIPT_NAME .. ".clientid-hex")
    if clientid then
      clientid = clientid:gsub(":", "")
      if not clientid:find("^%x+$") then
        return stdnse.format_output(false, "Invalid hexadecimal client ID")
      end
      clientid = stdnse.fromhex(clientid)
    end
  end
  if clientid then
    if #clientid == 0 or #clientid > 255 then
      return stdnse.format_output(false, "Client ID must be between 1 and 255 characters long")
    end
    table.insert(options, {number = 61, type = "string", value = clientid })
  end

  local interfaces

  -- first check if the user supplied an interface
  if ( nmap.get_interface() ) then
    interfaces = { [nmap.get_interface()] = true }
  else
    -- As the response will be sent to the "offered" ip address we need
    -- to use pcap to pick it up. However, we don't know what interface
    -- our packet went out on, so lets get a list of all interfaces and
    -- run pcap on all of them, if they're a) up and b) ethernet.
    interfaces = getInterfaces("ethernet", "up")
  end

  if( not(interfaces) ) then return fail("Failed to retrieve interfaces (try setting one explicitly using -e)") end

  local transaction_id = math.random(0, 0x7F000000)

  local threads = {}
  local result = {}
  local condvar = nmap.condvar(result)

  -- start a listening thread for each interface
  for iface, _ in pairs(interfaces) do
    transaction_id = transaction_id + 1
    local xid = string.pack(">I4", transaction_id)

    local sock, co
    sock = nmap.new_socket()
    sock:pcap_open(iface, 1500, true, "ip && udp dst port 68")
    co = stdnse.new_thread( dhcp_listener, sock, iface, macaddr, options, timeout, xid, result )
    threads[co] = true
  end

  -- wait until all threads are done
  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  if not next(result) then
    return nil
  end

  local response = stdnse.output_table()
  -- Display the results
  for i, r in ipairs(result) do
    local result_table = stdnse.output_table()

    result_table["Interface"] = r.iface
    result_table["IP Offered"] = r.yiaddr_str
    for _, v in ipairs(r.options) do
      if(type(v.value) == 'table') then
        outlib.list_sep(v.value)
      end
      result_table[ v.name ] = v.value
    end

    response[string.format("Response %d of %d", i, #result)] = result_table
  end

  return response
end
