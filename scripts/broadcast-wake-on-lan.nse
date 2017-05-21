local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Wakes a remote system up from sleep by sending a Wake-On-Lan packet.
]]

---
-- @usage
-- nmap --script broadcast-wake-on-lan --script-args broadcast-wake-on-lan.MAC='00:12:34:56:78:9A'
--
-- @output
-- Pre-scan script results:
-- | broadcast-wake-on-lan:
-- |_  Sent WOL packet to: 10:9a:dd:a8:40:24
--
-- @args broadcast-wake-on-lan.MAC The MAC address of the remote system to wake up
-- @args broadcast-wake-on-lan.address The broadcast address to which the WoL packet is sent.
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

local MAC = stdnse.get_script_args("broadcast-wake-on-lan.MAC")
local address = stdnse.get_script_args("broadcast-wake-on-lan.address")

prerule = function()
  -- only run if we are ipv4 and have a MAC
  return (MAC ~= nil and nmap.address_family() == "inet")
end

-- Creates the WoL packet based on the remote MAC
-- @param mac string containing the MAC without delimiters
-- @return packet string containing the raw packet
local function createWOLPacket(mac)
  return "\xff\xff\xff\xff\xff\xff" .. string.rep(stdnse.fromhex(mac), 16)
end

local function fail (err) return stdnse.format_output(false, err) end

action = function()

  local MAC_hex
  if ( MAC:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x") ) then
    MAC_hex = MAC:gsub(":", "")
  elseif( MAC:match("%x%x%-%x%x%-%x%x%-%x%x%-%x%x%-%x%x") ) then
    MAC_hex = MAC:gsub("-", "")
  else
    return fail("Failed to process MAC address")
  end

  local host = { ip = address or "255.255.255.255" }
  local port = { number = 9, protocol = "udp" }
  local socket = nmap.new_socket("udp")

  -- send two packets, just in case
  for i=1,2 do
    local packet = createWOLPacket(MAC_hex)
    local status, err = socket:sendto(host, port, packet)
    if ( not(status) ) then
      return fail("Failed to send packet")
    end
  end
  return stdnse.format_output(true, ("Sent WOL packet to: %s"):format(MAC))
end

