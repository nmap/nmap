local ipOps = require "ipOps"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local target = require "target"

description = [[
Discovers Sonicwall firewalls which are directly attached (not routed) using
the same method as the manufacturers own 'SetupTool'. An interface needs to be
configured, as the script broadcasts a UDP packet.

The script needs to be run as a privileged user, typically root.

References:
* https://support.software.dell.com/kb/sw3677)
]]

---
-- @usage
-- nmap -e eth0 --script broadcast-sonicwall-discover
--
-- @output
-- | broadcast-sonicwall-discover:
-- |   192.168.5.1
-- |     MAC/Serial: 0006B1001122
-- |     Subnetmask: 255.255.255.0
-- |     Firmware: 3.9.1.2
-- |_    ROM: 14.0.1.1
--
-- @args broadcast-sonicwall-discover.timeout time in seconds to wait for a response
--       (default: 1s)

author = "Raphael Hoegger"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


-- preliminary checks
local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("Not running for lack of privileges.")
    return false
  end

  local has_interface = ( interface ~= nil )
  if ( not(has_interface) ) then
    stdnse.verbose1("No network interface was supplied, aborting.")
    return false
  end
  return true
end

action = function(host, port)
  local sock, co
  sock = nmap.new_socket()

  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 1) * 1000

  -- listen for a response
  sock:set_timeout(timeout)
  sock:pcap_open(interface, 1500, false, "ip && udp && port 26214 && greater 57")
  send_discover()

  local start_time = nmap.clock_ms()
  local results = stdnse.output_table()
  while( nmap.clock_ms() - start_time < timeout ) do
    local status, plen, _, layer3 = sock:pcap_receive()
    -- stop once we picked up our response
    if ( status ) then
      sock:close()
      local p = packet.Packet:new( layer3, #layer3)

      if ( p and p.udp_dport ) then
        -- parsing the result
        local IP = string.sub(layer3:sub(41), 0,4)
        IP = ipOps.str_to_ip(IP)
        local Netmask = string.sub(layer3:sub(45), 0,4)
        Netmask = ipOps.str_to_ip(Netmask)
        local Serial = string.sub(layer3:sub(49), 0,6)
        Serial = stdnse.tohex(Serial)
        local Romversion = string.sub(layer3:sub(55), 0,2)
        local ROMM = stdnse.tohex(Romversion, {separator=".", group=1})
        ROMM = string.gsub(ROMM, "[0-9a-f]", function(n) return tonumber(n, 16) end)
        local Firmwareversion = string.sub(layer3:sub(57), 0,2)
        local FIRMM = stdnse.tohex(Firmwareversion, {separator=".", group=1})
        FIRMM = string.gsub(FIRMM, "[0-9a-f]", function(n) return tonumber(n, 16) end)

        -- add nodes
        if target.ALLOW_NEW_TARGETS then
          target.add(IP)
        end

        local output = stdnse.output_table()
        output['MAC/Serial'] = Serial
        output['Subnetmask'] = Netmask
        output['Firmware'] = FIRMM
        output['ROM Version'] = ROMM
        results[IP] = output
      end
    end
    sock:close()
  end
  if #results > 0 then
    return results
  end
end

function send_discover()
  local host="255.255.255.255"
  local port="26214"
  local socket = nmap.new_socket("udp")

  local status = socket:sendto(host, port, "ackfin ping\00")
  if not status then return end
  socket:close()

  return true
end
