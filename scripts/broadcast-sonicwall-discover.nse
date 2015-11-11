local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local target = require "target"

description = [[
Discovers Sonicwall firewalls which are directly attached (not routed) using
the same method as the manufacturers own 'SetupTool'. An interface needs to be
configured, as the script broadcasts a UDP packet.
See: https://support.software.dell.com/fr-fr/kb/sw3677)

The script needs to be run as a privileged user, typically root.
]]

---
-- @usage
-- sudo nmap -e eth0 --script broadcast-sonicwall-discover
-- 
-- @output
-- | broadcast-sonicwall-discover: 
-- |   MAC/Serial: 0006B1001122
-- |   IP Address: 192.168.5.1
-- |   Subnetmask: 255.255.255.0
-- |   Firmware: 3.9.1.2
-- |_  ROM: 14.0.1.1
--
-- @args broadcast-sonicwall-discover.timeout time in seconds to wait for a response
--       (default: 1s)

author = "Raphael Hoegger"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


-- preliminary checks
local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

prerule = function()
  if not nmap.is_privileged() then
    stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
    return false
  end

  local has_interface = ( interface ~= nil )
  if ( not(has_interface) ) then
    stdnse.print_verbose("%s no network interface was supplied, aborting ...", SCRIPT_NAME)
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
  while( nmap.clock_ms() - start_time < timeout ) do
    local status, plen, _, layer3 = sock:pcap_receive()
    -- stop once we picked up our response
    if ( status ) then
      sock:close()
      local p = packet.Packet:new( layer3, #layer3)

      if ( p and p.udp_dport ) then
        -- parsing the result
        local IP
        local Serial
        local Subnetmask
        local Firmwareversion
        local Romversion

        local IP=string.sub(layer3:sub(41), 0,4)
        local Netmask=string.sub(layer3:sub(45), 0,4)
        local Serial=string.sub(layer3:sub(49), 0,6)
        local Romversion=string.sub(layer3:sub(55), 0,2)
        local Firmwareversion=string.sub(layer3:sub(57), 0,2)
        
        local pos, Serial = bin.unpack("H6", Serial)
        local pos, oct1, oct2, oct3, oct4 = bin.unpack(">CCCC", IP)
        IP=oct1 .. '.' .. oct2 .. '.' .. oct3 .. '.' .. oct4
        
        local pos, oct1, oct2, oct3, oct4 = bin.unpack(">CCCC", Netmask)
        Netmask=oct1 .. '.' .. oct2 .. '.' .. oct3 .. '.' .. oct4
        
        local pos, Romversion = bin.unpack("H2", Romversion)
        local ROMM=""
        for i = 1, string.len(Romversion) do
          if (i == 1) then
            ROMM = tonumber(string.sub(Romversion, i, i),16)
          else
            ROMM = ROMM .. "." .. tonumber(string.sub(Romversion, i, i),16)
          end
        end

        local pos, Firmwareversion = bin.unpack("H2", Firmwareversion)
        local FIRMM=""
        for i = 1, string.len(Firmwareversion) do
          if (i == 1) then
            FIRMM = tonumber(string.sub(Firmwareversion, i, i),16)
          else
            FIRMM = FIRMM .. "." .. tonumber(string.sub(Firmwareversion, i, i),16)
          end
        end

        -- add nodes
        target.add(IP)

        local output='MAC/Serial: ' .. Serial
        local output=output .. '\nIP address: ' .. IP
        local output=output .. '\nSubnetmask: ' .. Netmask
        local output=output .. '\nFirmware: ' .. FIRMM
        local output=output .. '\nROM Version: ' .. ROMM
        return stdnse.format_output(true, output)
        end
      end
    sock:close()
   end
end
       
function send_discover()
  local host="255.255.255.255"
  local port="26214"
  local socket = nmap.new_socket()
  
  socket:connect(host, port, "udp")
  socket:send("ackfin ping\00")
  socket:close()
  
  return true  
end

