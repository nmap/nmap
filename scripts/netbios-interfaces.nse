local netbios = require "netbios"
local nmap = require "nmap"
local string = require "string"
local tab = require "tab"

description = [[
Attempts to retrieve the target's network interfaces.
It is very useful for finding pathes to isolated networks.
]]

---
-- @usage
-- sudo nmap -sU --script netbios-interfaces.nse -p137 <host>
--
-- @output
-- Host script results:
-- | netbios-interfaces: 
-- | 10.0.0.64
-- |_12.0.0.1



author = {"Andrey Zhukov from USSC"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


hostrule = function(host)

  -- The following is an attempt to only run this script against hosts
  -- that will probably respond to a UDP 137 probe.  One might argue
  -- that sending a single UDP packet and waiting for a response is no
  -- big deal and that it should be done for every host.  In that case
  -- simply change this rule to always return true.

  local port_t135 = nmap.get_port_state(host,
    {number=135, protocol="tcp"})
  local port_t139 = nmap.get_port_state(host,
    {number=139, protocol="tcp"})
  local port_t445 = nmap.get_port_state(host,
    {number=445, protocol="tcp"})
  local port_u137 = nmap.get_port_state(host,
    {number=137, protocol="udp"})

  return (port_t135 ~= nil and port_t135.state == "open") or
    (port_t139 ~= nil and port_t139.state == "open") or
    (port_t445 ~= nil and port_t445.state == "open") or
    (port_u137 ~= nil and
      (port_u137.state == "open" or
      port_u137.state == "open|filtered"))
end

get_ip = function(buf)
  return tostring(string.byte(buf:sub(1,2))) .. "." .. tostring(string.byte(buf:sub(2,3))) .. "." .. tostring(string.byte(buf:sub(3,4))) .. "." .. tostring(string.byte(buf:sub(4,5)))
end

action = function(host)
  local outtab = tab.new(1)
  local status, server_name = netbios.get_server_name(host)
  local status, result = netbios.nbquery(host, server_name, { multiple = true })
  for k, v in ipairs(result) do
    for i=1,string.len(v.data),6 do
      tab.addrow(outtab, get_ip(v.data:sub(i+2,i+2+4)))
    end
  end
  return "\n" .. tab.dump(outtab)
end
