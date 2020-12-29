local shortport = require "shortport"
local netbios = require "netbios"
local string = require "string"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to retrieve via NetBIOS the target's network interfaces.
Additional network interfaces may reveal more information about target.
In particular, it is very useful for finding paths to non-routed networks if target has more than one NIC.
]]

---
-- @usage
-- nmap -sU --script netbios-interfaces.nse -p 137 <host>
--
-- @output
-- PORT    STATE SERVICE
-- 137/udp open  netbios-ns
-- | netbios-interfaces: 
-- |   hostname: NOTEBOOK-NB3
-- |   interfaces: 
-- |     10.5.4.89
-- |     192.168.56.1
-- |     172.24.80.1
-- MAC Address: 9C:7B:EF:AA:BB:CC (Hewlett Packard)
--
-- @xmloutput
-- <table key="interfaces">
-- <elem>10.5.4.89</elem>
-- <elem>192.168.56.1</elem>
-- <elem>172.24.80.1</elem>
-- </table>


author = {"Andrey Zhukov from USSC"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.portnumber(137, "udp")

get_ip = function(buf)
  return table.concat({buf:byte(1, 4)}, ".")
end

action = function(host)
  local output = stdnse.output_table()
  local status, server_name = netbios.get_server_name(host)
  if(not(status)) then
    return stdnse.format_output(false, "Failed to get NetBIOS name of the target")
  end
  local status, result = netbios.nbquery(host, server_name)
  if(not(status)) then
    return stdnse.format_output(false, "Failed to get remote network interfaces")
  end
  output.hostname = server_name
  output.interfaces = {}
  for k, v in ipairs(result) do
    for i=1,string.len(v.data),6 do
      output.interfaces[#output.interfaces + 1] = get_ip(v.data:sub(i+2,i+2+4-1))
    end
  end
  return output
end
