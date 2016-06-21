local stdnse    = require "stdnse"
local shortport = require "shortport"
local isns      = require "isns"
local tab       = require "tab"
local table     = require "table"

description = [[
Lists portals and iSCSI nodes registered with the Internet Storage Name
Service (iSNS).
]]

---
-- @usage
-- nmap -p 3205 <ip> --script isns-info
--
-- @output
-- PORT     STATE SERVICE
-- 3205/tcp open  unknown
-- | isns-info:
-- |   Portal
-- |     ip             port
-- |     192.168.0.1    3260/tcp
-- |     192.168.0.2    3260/tcp
-- |   iSCSI Nodes
-- |     node                                              type
-- |     iqn.2001-04.com.example:storage.disk2.sys1.xyz    Target
-- |     iqn.2001-05.com.example:storage.disk2.sys1.xyz    Target
-- |_    iqn.2001-04.a.com.example:storage.disk3.sys2.abc  Target
--

portrule = shortport.port_or_service(3205, 'isns')

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  local helper = isns.Helper:new(host, port)
  if ( not(helper:connect()) ) then
    return fail("Failed to connect to server")
  end

  local status, portals = helper:listPortals()
  if ( not(status) ) then
    return
  end

  local results = {}
  local restab = tab.new(2)
  tab.addrow(restab, "ip", "port")
  for _, portal in ipairs(portals) do
    tab.addrow(restab, portal.addr, ("%d/%s"):format(portal.port, portal.proto))
  end
  table.insert(results, { name = "Portal", tab.dump(restab) })

  local status, nodes = helper:listISCINodes()
  if ( not(status) ) then
    return
  end

  restab = tab.new(2)
  tab.addrow(restab, "node", "type")
  for _, portal in ipairs(nodes) do
    tab.addrow(restab, portal.name, portal.type)
  end
  table.insert(results, { name = "iSCSI Nodes", tab.dump(restab) })

  return stdnse.format_output(true, results)
end
