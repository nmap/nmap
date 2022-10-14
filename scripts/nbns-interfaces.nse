local shortport = require "shortport"
local netbios = require "netbios"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves IP addresses of the target's network interfaces via NetBIOS NS.
Additional network interfaces may reveal more information about the target,
including finding paths to hidden non-routed networks via multihomed systems.
]]

---
-- @usage
-- nmap -sU -p 137 --script nbns-interfaces <host>
--
-- @output
-- PORT    STATE SERVICE
-- 137/udp open  netbios-ns
-- | nbns-interfaces:
-- |   hostname: NOTEBOOK-NB3
-- |   interfaces:
-- |     10.5.4.89
-- |     192.168.56.1
-- |_    172.24.80.1
-- MAC Address: 9C:7B:EF:AA:BB:CC (Hewlett Packard)
--
-- @xmloutput
-- <elem key="hostname">NOTEBOOK-NB3</elem>
-- <table key="interfaces">
--   <elem>10.5.4.89</elem>
--   <elem>192.168.56.1</elem>
--   <elem>172.24.80.1</elem>
-- </table>
---

author = {"Andrey Zhukov from USSC"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = nmap.address_family() == 'inet' -- NBNS is IPv4 only
           and shortport.portnumber(137, "udp")
           or function () return false end

get_ip = function (buf)
  return table.concat({buf:byte(1, 4)}, ".")
end

action = function (host)
  local output = stdnse.output_table()
  local status, server_name = netbios.get_server_name(host)
  if not (status and server_name) then
    return stdnse.format_output(false, "Failed to get NetBIOS server name of the target")
  end
  local status, result = netbios.nbquery(host, server_name)
  if not status then
    return stdnse.format_output(false, "Failed to get remote network interfaces")
  end
  output.hostname = server_name
  output.interfaces = {}
  for _, v in ipairs(result) do
    for i=1, #v.data, 6 do
      output.interfaces[#output.interfaces + 1] = get_ip(v.data:sub(i+2, i+2+3))
    end
  end
  return output
end
