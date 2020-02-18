local _G = require "_G"
local coroutine = require "coroutine"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Sniffs the network for incoming broadcast communication and
attempts to decode the received packets. It supports protocols like CDP, HSRP,
Spotify, DropBox, DHCP, ARP and a few more. See packetdecoders.lua for more
information.

The script attempts to sniff all ethernet based interfaces with an IPv4 address
unless a specific interface was given using the -e argument to Nmap.
]]

---
-- @usage
-- nmap --script broadcast-listener
-- nmap --script broadcast-listener -e eth0
--
-- @output
-- | broadcast-listener:
-- |   udp
-- |       Netbios
-- |         ip           query
-- |         192.168.0.60 \x01\x02__MSBROWSE__\x02\x01
-- |       DHCP
-- |         srv ip       cli ip       mask             gw           dns
-- |         192.168.0.1  192.168.0.5  255.255.255.0    192.168.0.1  192.168.0.18, 192.168.0.19
-- |       DropBox
-- |         displayname  ip            port   version  host_int  namespaces
-- |         39000860     192.168.0.107 17500  1.8      39000860  28814673, 29981099
-- |       HSRP
-- |         ip             version  op     state   prio  group  secret  virtual ip
-- |         192.168.0.254  0        Hello  Active  110   1      cisco   192.168.0.253
-- |   ether
-- |       CDP
-- |         ip  id      platform       version
-- |         ?   Router  cisco 7206VXR  12.3(23)
-- |       ARP Request
-- |         sender ip     sender mac         target ip
-- |         192.168.0.101 00:04:30:26:DA:C8  192.168.0.60
-- |_        192.168.0.1   90:24:1D:C8:B9:AE  192.168.0.60
--
-- @args broadcast-listener.timeout specifies the amount of seconds to sniff
--       the network interface. (default 30s)
--
-- The script attempts to discover all available ipv4 network interfaces,
-- unless the Nmap -e argument has been supplied, and then starts sniffing
-- packets on all of the discovered interfaces. It sets a BPF filter to exclude
-- all packets that have the interface address as source or destination in
-- order to capture broadcast traffic.
--
-- Incoming packets can either be either layer 3 (usually UDP) or layer 2.
-- Depending on the layer the packet is matched against a packet decoder loaded
-- from the external nselib/data/packetdecoder.lua file. A more detailed
-- description on how the decoders work can be found in that file.
-- In short, there are two different types of decoders: udp and ether.
-- The udp decoders get triggered by the destination port number, while the
-- ether decoders are triggered by a pattern match. The port or pattern is used
-- as an index in a table containing functions to process packets and fetch
-- the decoded results.
--


--
-- Version 0.1
-- Created 07/02/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/25/2011 - v0.2 -
--                * added more documentation
--                * added getInterfaces code to detect available
--                  interfaces.
--                * corrected bug that would fail to load
--                  decoders if not in a relative directory.



author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}




prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end
  return true
end

---
-- loads the decoders from file
--
-- @param fname string containing the name of the file
-- @return status true on success false on failure
-- @return decoders table of decoder functions on success
-- @return err string containing the error message on failure
loadDecoders = function(fname)
  -- resolve the full, absolute, path
  local abs_fname = nmap.fetchfile(fname)

  if ( not(abs_fname) ) then
    return false, ("Failed to load decoder definition (%s)"):format(fname)
  end

  local env = setmetatable({Decoders = {}}, {__index = _G});
  local file = loadfile(abs_fname, "t", env)
  if(not(file)) then
    stdnse.debug1("Couldn't load decoder file: %s", fname)
    return false, "Couldn't load decoder file: " .. fname
  end

  file()

  local d = env.Decoders

  if ( d ) then return true, d end
  return false, "Failed to load decoders"
end

---
-- Starts sniffing the selected interface for packets with a destination that
-- is not explicitly ours (broadcast, multicast etc.)
--
-- @param iface table containing <code>name</code> and <code>address</code>
-- @param Decoders the decoders class loaded externally
-- @param decodertab the "result" table to which all discovered items are
--      reported
sniffInterface = function(iface, Decoders, decodertab)
  local condvar = nmap.condvar(decodertab)
  local sock = nmap.new_socket()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args("broadcast-listener.timeout"))

  -- default to 30 seconds, if nothing else was set
  timeout = (timeout or 30) * 1000

  -- We want all packets that aren't explicitly for us
  sock:pcap_open(iface.name, 1500, true, ("!host %s"):format(iface.address))

  -- Set a short timeout so that we can timeout in time if needed
  sock:set_timeout(100)

  local start_time = nmap.clock_ms()
  while( nmap.clock_ms() - start_time < timeout ) do
    local status, _, _, data = sock:pcap_receive()

    if ( status ) then
      local p = packet.Packet:new( data, #data )

      -- if we have an UDP-based broadcast, we should have a proper packet
      if ( p and p.udp_dport and ( decodertab.udp[p.udp_dport] or Decoders.udp[p.udp_dport] ) ) then
        local uport = p.udp_dport
        if ( not(decodertab.udp[uport]) ) then
          decodertab.udp[uport] = Decoders.udp[uport]:new()
        end
        stdnse.new_thread(decodertab.udp[uport].process, decodertab.udp[uport], data)
        -- The packet was decoded successfully but we don't have a valid decoder
        -- Report this
      elseif ( p and p.udp_dport ) then
        stdnse.debug2("No decoder for dst port %d", p.udp_dport)
        -- we don't have a packet, so this is most likely something layer2 based
        -- in that case, check the ether Decoder table for pattern matches
      else
        -- attempt to find a match for a pattern
        local hex = stdnse.tohex(data)
        local decoded = false
        for match, _ in pairs(Decoders.ether) do
          -- attempts to match the "raw" packet against a filter
          -- supplied in each ethernet packet decoder
          if ( hex:match(match) ) then
            stdnse.debug1("Packet matched '%s'", match)
            if ( not(decodertab.ether[match]) ) then
              decodertab.ether[match] = Decoders.ether[match]:new()
            end
            -- start a new decoding thread. This way, if something gets foobared
            -- the whole script doesn't break, only the packet decoding for that
            -- specific packet.
            stdnse.new_thread( decodertab.ether[match].process, decodertab.ether[match], data )
            decoded = true
          end
        end
        -- no decoder was found for this layer2 packet
        if ( not(decoded) and #data > 10 ) then
          stdnse.debug1("No decoder for packet hex: %s", stdnse.tohex(data:sub(1,10)))
        end
      end
    end
  end
  condvar "signal"
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
getInterfaces = function(link, up)
  if( not(nmap.list_interfaces) ) then return end
  local interfaces, err = nmap.list_interfaces()
  local result = {}
  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
      if ( iface.link == link and
        iface.up == up and
        iface.address ) then

        -- exclude ipv6 addresses for now
        if ( not(iface.address:match(":")) ) then
          table.insert(result, { name = iface.device,
          address = iface.address } )
        end
      end
    end
  end
  return result
end

local function fail (err) return stdnse.format_output(false, err) end

action = function()

  local DECODERFILE = "nselib/data/packetdecoders.lua"
  local iface = nmap.get_interface()
  local interfaces = {}

  -- was an interface supplied using the -e argument?
  if ( iface ) then
    local iinfo, err = nmap.get_interface_info(iface)

    if ( not(iinfo.address) ) then
      return fail("The IP address of the interface could not be determined")
    end

    interfaces = { { name = iface, address = iinfo.address } }
  else
    -- no interface was supplied, attempt autodiscovery
    interfaces = getInterfaces("ethernet", "up")
  end

  -- make sure we have at least one interface to start sniffing
  if ( #interfaces == 0 ) then
    return fail("Could not determine any valid interfaces")
  end

  -- load the decoders from file
  local status, Decoders = loadDecoders(DECODERFILE)
  if ( not(status) ) then return fail(Decoders) end

  -- create a local table to handle instantiated decoders
  local decodertab = { udp = {}, ether = {} }
  local condvar = nmap.condvar(decodertab)
  local threads = {}

  -- start a thread for each interface to sniff
  for _, iface in ipairs(interfaces) do
    local co = stdnse.new_thread(sniffInterface, iface, Decoders, decodertab)
    threads[co] = true
  end

  -- wait for all threads to finish sniffing
  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then
        threads[thread] = nil
      end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  local out_outer = {}

  -- create the results table
  for proto, _ in pairs(decodertab) do
    local out_inner = {}
    for key, decoder in pairs(decodertab[proto]) do
      table.insert( out_inner, decodertab[proto][key]:getResults() )
    end
    if ( #out_inner > 0 ) then
      table.insert( out_outer, { name = proto, out_inner } )
    end
  end

  table.sort(out_outer, function(a, b) return a.name < b.name end)
  return stdnse.format_output(true, out_outer)

end
