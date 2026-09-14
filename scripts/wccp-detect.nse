local wccp = require "wccp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
  Performs WCCP Discovery through Hear I Am probes.
]]

---
-- @usage
-- nmap -sU --script wccp-detect -p 2048 <host>
--
-- @output
-- PORT     STATE SERVICE  REASON
-- 2048/udp  open|filtered  unknown
-- | wccp-detect:
-- |   ServiceType: Standard, Dynamic
-- |   Security: None
-- |_  ServiceIDs: 0,...,255
--
-- @xmloutput
-- <table>
--   <table key="ServiceType">
--     <elem>Standard</elem>
--     <elem>Dynamic</elem>
--   </table>
--
--   <table key="Security">
--     <elem>None</elem>
--   </table>
--
--   <table key="ServiceIDs">
--     <elem>0</elem>
--     <elem>...</elem>
--     <elem>255</elem>
--   </table>
--
--   <table key="Level">
--     <elem>1.2</elem>
--     <elem>2.0</elem>
--   </table>
-- </table>
--

author = "Benjamin Jones <ben@benjaminjones.me>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.version_port_or_service(2048, "dls-monitor", "udp", {"open", "open|filtered"})

local comma_separated = {
  __tostring = function(t) return table.concat(t, ", ") end
}

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(500)
  socket:bind("0.0.0.0", 2048)
  socket:connect(host, 2048, "udp")
  local status, lhost, lport, rhost, rport = socket:get_info()
  stdnse.debug1(string.format("lhost = %s", lhost))


  -- Send a probe to each service ID
  local svcid_response = {}

  local request = wccp.wccp_hia_message(host.ip, lhost, 0x0, nil)

  for id=0,255 do
    if id ~= 0 then
      local port_spec = {443,0,0,0,0,0,0,0} -- Doesn't really matter
      request = wccp.wccp_hia_message(host.ip, lhost, id, port_spec)
    end
    socket:send(request)
    local status, reply = socket:receive()
    if status then
      svcid_response[id] = wccp.wccp_parse_isy(reply)
    end
  end
  socket:close()
  
  if next(svcid_response) == nil then
    return nil
  end
  nmap.set_port_state(host, port, "open")

  local ServType = {}
  local ServIDs = {}
  setmetatable(ServType, comma_separated)
  setmetatable(ServIDs, comma_separated)
  if svcid_response[0] == true then
    table.insert(ServType, "Standard")
  end

  for i=1,255 do
    if svcid_response[i] ~= nil then
      table.insert(ServType, "Dynamic")
      break
    end
  end

  for i=0,255 do
    if svcid_response[i] ~= nil then
      table.insert(ServIDs, i)
    end
  end
 
  local SecType = {}
  table.insert(SecType, "None")

  local output = stdnse.output_table()
  output["ServiceType"] = ServType
  output["Security"] = SecType
  output["ServiceIDs"] = ServIDs

  return output
end
