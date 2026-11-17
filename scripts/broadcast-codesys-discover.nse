local nmap = require "nmap"
local ipOps = require "ipOps"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local codesys3 = require "codesys3"


description=[[
Discovers hosts running a Codesys V3 PLC runtime on the LAN. It does so by
sending a broadcast packet with a device discovery request in a proprietary and
undocumented Codesys network protocol and then collects all responses from
devices on the network.
]]

---
-- @usage
-- nmap --script broadcast-codesys-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-codesys-discover: 
-- |   192.168.20.7: 
-- |     interface: enp11s0f0.20
-- |     targetVendor: 3S - Smart Software Solutions GmbH
-- |     targetName: CODESYS Control for Raspberry Pi MC SL
-- |     deviceName: raspberrypi
-- |     targetID: 0x11
-- |     targetType: 0x1006
-- |     targetVersion: 3.5.15.10
-- |   192.168.20.10: 
-- |     interface: enp11s0f0.20
-- |     targetVendor: WAGO
-- |     targetName: WAGO 750-8215 PFC200 G2 4ETH CAN USB
-- |     deviceName: PFC200V3-4538EF
-- |     targetID: 0x1006120b
-- |     targetType: 0x1000
-- |     targetVersion: 5.15.4.0
-- |   192.168.20.9: 
-- |     interface: enp11s0f0.20
-- |     targetVendor: WAGO
-- |     targetName: WAGO 750-8206 PFC200 2ETH RS CAN DPS
-- |     deviceName: PFC200-438F4C
-- |     targetID: 0x10061204
-- |     targetType: 0x1000
-- |_    targetVersion: 5.15.4.0
--
-- @args broadcast-codesys-discover.timeout timespec defining how long to wait
--       for a response. (default 3s)

--
-- Version 0.1
-- Created 23/06/2021 - v0.1 - created by Andreas Galauner <agalauner@rapid7.com>
--

author = "Andreas Galauner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function()
    if nmap.address_family() ~= 'inet' then
        stdnse.debug1("is IPv4 compatible only.")
        return false
    end

    if not nmap.is_privileged() then
      stdnse.verbose1("Not running due to lack of privileges.")
      return false
    end

    return true
end

---
-- Gets a list of available interfaces based on link and up filters
-- Interfaces are only added if they've got an ipv4 address
--
-- @param link string containing the link type to filter
-- @param up string containing the interface status to filter
-- @return result table containing tables of interfaces
--      each interface table has the following fields:
--      <code>name</code> containing the device name
--      <code>address</code> containing the device address
--      <code>netmask</code> containing the device netmask
--      <code>broadcast</code> containing the device broadcast address
getInterfaces = function(link, up)
  local interfaces, err = nmap.list_interfaces()
  local result = {}
  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
      if ( iface.link == link and
        iface.up == up and
        iface.address ) then

        -- exclude ipv6 addresses for now
        if ( not(iface.address:match(":")) ) then
          table.insert(result, {
            name = iface.device,
            address = iface.address,
            netmask = iface.netmask,
            broadcast = iface.broadcast
          })
        end
      end
    end
  end
  return result
end

local function codesys_listener(sock, iface, timeout, result)
  local condvar = nmap.condvar(result)

  local start_time = nmap.clock_ms()
  local now = start_time
  while( now - start_time < timeout ) do
    sock:set_timeout(timeout - (now - start_time))
    local status, _, _, data = sock:pcap_receive()

    if ( status ) then
      local p = packet.Packet:new( data, #data )
      if ( p and p.udp_dport ) then
        local data = data:sub(p.udp_offset + 9)
        local status, response = codesys3.CodesysV3.NameServiceResponse:new(data)
        if ( status ) then
          response.iface = iface.name
          response.ip = p.ip_src
          table.insert(result, response)
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
  local timeout = stdnse.parse_timespec(stdnse.get_script_args('broadcast-codesys-discover.timeout'))
  timeout = (timeout or 3) * 1000

  local iface = nmap.get_interface()
  local interfaces = {}

  -- was an interface supplied using the -e argument?
  if ( iface ) then
    local iinfo, err = nmap.get_interface_info(iface)

    if ( not(iinfo.address) ) then
      return fail("The IP address of the interface could not be determined")
    end

    interfaces = { { name = iface, address = iinfo.address, netmask = iinfo.netmask, broadcast = iinfo.broadcast } }
  else
    -- no interface was supplied, attempt autodiscovery
    interfaces = getInterfaces("ethernet", "up")
  end

  -- make sure we have at least one interface to run discovery on
  if ( #interfaces == 0 ) then
    return fail("Could not determine any valid interfaces, try to set one explicitly using -e")
  end

  stdnse.debug1("Determined the following interfaces to run discovery on:")
  for _, iface in ipairs(interfaces) do
    stdnse.debug1("%s: IP: %s - Netmask: %s - Broadcast: %s", iface.name, iface.address, iface.netmask, iface.broadcast)
  end

  local result = {}
  local threads = {}
  local condvar = nmap.condvar(result)

  -- start a listening thread for each interface
  for _, iface in ipairs(interfaces) do
    local sock, co
    sock = nmap.new_socket()
    sock:pcap_open(iface.name, 1500, false, "ip && udp && port 1743")
    co, info = stdnse.new_thread(codesys_listener, sock, iface, timeout, result)
    threads[co] = info
  end

  -- Send out probes on all interfaces
  for _, iface in ipairs(interfaces) do
    local source_port = 1743

    local socket = nmap.new_socket("udp")
    socket:set_timeout(timeout)

    -- Send name service requests to all 4 codesys UDP ports
    for i=0,3 do
      local destination_port = 1740+i
      local cs = codesys3.CodesysV3.NameServiceRequest:new(3, iface.address, iface.netmask)
      local packet = tostring(cs)

      socket:bind(iface.address, source_port)
      local status, err = socket:sendto(iface.broadcast, destination_port, packet)

      if ( not(status) ) then
        return false, string.format("Failed to send broadcast packet to UDP port %d", destination_port)
      end
    end
  end

  -- wait until all threads are done
  repeat
    for thread, info in pairs(threads) do
      if info() == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  if not next(result) then
    return nil
  end

  -- Display the results
  local response = stdnse.output_table()
  local ips = stdnse.output_table()

  for _, r in ipairs(result) do
    local out = stdnse.output_table()

    out["interface"] = r.iface
    out["targetVendor"] = r.vendorName
    out["targetName"] = r.deviceName
    out["deviceName"] = r.nodeName
    out["targetID"] = string.format("0x%x", r.targetId)
    out["targetType"] = string.format("0x%x", r.targetType)
    out["targetVersion"] = codesys3.version_to_str(r.targetVersion)

    response[r.ip] = out
    ips[#ips+1] = r.ip
  end

  -- sort by IP address and reorder the results to get a stable output between different runs
  ipOps.ip_sort(ips)
  for _, ip in ipairs(ips) do
    local tmp = response[ip]
    response[ip] = nil
    response[ip] = tmp
  end

  return response
end
