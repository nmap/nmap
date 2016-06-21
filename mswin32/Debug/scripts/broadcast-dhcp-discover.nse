local bin = require "bin"
local coroutine = require "coroutine"
local dhcp = require "dhcp"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends a DHCP request to the broadcast address (255.255.255.255) and reports
the results. The script uses a static MAC address (DE:AD:CO:DE:CA:FE) while
doing so in order to prevent scope exhaustion.

The script reads the response using pcap by opening a listening pcap socket
on all available ethernet interfaces that are reported up. If no response
has been received before the timeout has been reached (default 10 seconds)
the script will abort execution.

The script needs to be run as a privileged user, typically root.
]]

---
-- @usage
-- sudo nmap --script broadcast-dhcp-discover
--
-- @output
-- | broadcast-dhcp-discover:
-- |   IP Offered: 192.168.1.114
-- |   DHCP Message Type: DHCPOFFER
-- |   Server Identifier: 192.168.1.1
-- |   IP Address Lease Time: 1 day, 0:00:00
-- |   Subnet Mask: 255.255.255.0
-- |   Router: 192.168.1.1
-- |   Domain Name Server: 192.168.1.1
-- |_  Domain Name: localdomain
--
-- @xmloutput
-- <elem key="IP Offered">192.168.1.114</elem>
-- <elem key="DHCP Message Type">DHCPOFFER</elem>
-- <elem key="Server Identifier">192.168.1.1</elem>
-- <elem key="IP Address Lease Time">1 day, 0:00:00</elem>
-- <elem key="Subnet Mask">255.255.255.0</elem>
-- <elem key="Router">192.168.1.1</elem>
-- <elem key="Domain Name Server">192.168.1.1</elem>
-- <elem key="Domain Name">localdomain</elem>
--
-- @args broadcast-dhcp-discover.timeout time in seconds to wait for a response
--       (default: 10s)
--

-- Version 0.1
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

-- Creates a random MAC address
--
-- @return mac_addr string containing a random MAC
local function randomizeMAC()
  local mac_addr = {}
  for j=1, 6 do
    mac_addr[j] = string.char(math.random(1, 255))
  end
  return table.concat(mac_addr)
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
-- @param timeout number of ms to wait for a response
-- @param xid the DHCP transaction id
-- @param result a table to which the result is written
local function dhcp_listener(sock, timeout, xid, result)
  local condvar = nmap.condvar(result)

  sock:set_timeout(100)

  local start_time = nmap.clock_ms()
  while( nmap.clock_ms() - start_time < timeout ) do
    local status, _, _, data = sock:pcap_receive()
    -- abort, once another thread has picked up our response
    if ( #result > 0 ) then
      sock:close()
      condvar "signal"
      return
    end

    if ( status ) then
      local p = packet.Packet:new( data, #data )
      if ( p and p.udp_dport ) then
        local data = data:sub(p.udp_offset + 9)
        local status, response = dhcp.dhcp_parse(data, xid)
        if ( status ) then
          table.insert( result, response )
          sock:close()
          condvar "signal"
          return
        end
      end
    end
  end
  sock:close()
  condvar "signal"
end

local commasep = {
  __tostring = function (t)
    return table.concat(t, ", ")
  end
}

local function fail (err) return stdnse.format_output(false, err) end

action = function()

  local host, port = "255.255.255.255", 67
  local timeout = stdnse.parse_timespec(stdnse.get_script_args("broadcast-dhcp-discover.timeout"))
  timeout = (timeout or 10) * 1000

  -- randomizing the MAC could exhaust dhcp servers with small scopes
  -- if ran multiple times, so we should probably refrain from doing
  -- this?
  local mac = "\xDE\xAD\xC0\xDE\xCA\xFE" --randomizeMAC()

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

  local transaction_id = bin.pack("<I", math.random(0, 0x7FFFFFFF))
  local request_type = dhcp.request_types["DHCPDISCOVER"]
  local ip_address = bin.pack(">I", ipOps.todword("0.0.0.0"))

  -- we need to set the flags to broadcast
  local request_options, overrides, lease_time = nil, { flags = 0x8000 }, nil
  local status, packet = dhcp.dhcp_build(request_type, ip_address, mac, nil, request_options, overrides, lease_time, transaction_id)
  if (not(status)) then return fail("Failed to build packet") end

  local threads = {}
  local result = {}
  local condvar = nmap.condvar(result)

  -- start a listening thread for each interface
  for iface, _ in pairs(interfaces) do
    local sock, co
    sock = nmap.new_socket()
    sock:pcap_open(iface, 1500, false, "ip && udp && port 68")
    co = stdnse.new_thread( dhcp_listener, sock, timeout, transaction_id, result )
    threads[co] = true
  end

  local socket = nmap.new_socket("udp")
  socket:bind(nil, 68)
  socket:sendto( host, port, packet )
  socket:close()

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

    result_table["IP Offered"] = r.yiaddr_str
    for _, v in ipairs(r.options) do
      if(type(v.value) == 'table') then
        setmetatable(v.value, commasep)
      end
      result_table[ v.name ] = v.value
    end

    response[string.format("Response %d of %d", i, #result)] = result_table
  end

  return response
end
