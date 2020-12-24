local shortport = require "shortport"
local netbios = require "netbios"
local string = require "string"
local stdnse = require "stdnse"

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
-- |     192.168.128.100
-- |     172.24.80.1
-- |     172.27.96.1
-- MAC Address: 9C:7B:EF:AA:BB:CC (Hewlett Packard)


author = {"Andrey Zhukov from USSC"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.portnumber(137, "udp", {"open", "open|filtered"})

get_ip = function(buf)
  return table.concat({buf:byte(1, 4)}, ".")
end

action = function(host)
  local output = stdnse.output_table()
  local status, server_name = netbios.get_server_name(host)
  if(not(status)) then
    return output, "Failed to get hostname"
  end
  local status, result = netbios.nbquery(host, server_name, { multiple = true })
  if(not(status)) then
    return output, "Failed to get remote network interfaces"
  end
  output.hostname = server_name
  output.interfaces = {}
  for k, v in ipairs(result) do
    for i=1,string.len(v.data),6 do
      output.interfaces[#output.interfaces + 1] = get_ip(v.data:sub(i+2,i+2+4))
    end
  end
  return output, ""
end
