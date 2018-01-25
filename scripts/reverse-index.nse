local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Creates a reverse index at the end of scan output showing which hosts run a
particular service.  This is in addition to Nmap's normal output listing the
services on each host.
]]

---
-- @usage
-- nmap --script reverse-index <hosts/networks>
--
-- @output
-- Post-scan script results:
-- | reverse-index:
-- |   22/tcp: 192.168.0.60
-- |   23/tcp: 192.168.0.100
-- |   80/tcp: 192.168.0.70
-- |   445/tcp: 192.168.0.1
-- |   53/udp: 192.168.0.1, 192.168.0.60, 192.168.0.70, 192.168.0.105
-- |_  5353/udp: 192.168.0.1, 192.168.0.60, 192.168.0.70, 192.168.0.105
--
-- @args reverse-index.mode the output display mode, can be either horizontal
--       or vertical (default: horizontal)
-- @args reverse-index.names If set, index results by service name instead of
--       port number. Unknown services will be listed by port number.
--
-- @xmloutput
-- <table key="ftp/tcp">
--   <elem>127.0.0.1</elem>
-- </table>
-- <table key="http/tcp">
--   <elem>45.33.32.156</elem>
--   <elem>127.0.0.1</elem>
--   <elem>172.217.9.174</elem>
-- </table>
-- <table key="https/tcp">
--   <elem>172.217.9.174</elem>
-- </table>
-- <table key="smtp/tcp">
--   <elem>127.0.0.1</elem>
-- </table>
-- <table key="ssh/tcp">
--   <elem>45.33.32.156</elem>
--   <elem>127.0.0.1</elem>
-- </table>
--

-- Version 0.1
-- Created 11/22/2011 - v0.1 - created by Patrik Karlsson
author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe" }

-- the postrule displays the reverse-index once all hosts are scanned
postrule = function() return true end

-- the hostrule iterates over open ports for the host and pushes them into the registry
hostrule = function() return true end

hostaction = function(host)
  local names = stdnse.get_script_args(SCRIPT_NAME .. ".names")
  stdnse.debug1("names = %s", names)
  nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {tcp={}, udp={}}
  local db = nmap.registry[SCRIPT_NAME]
  for _, s in ipairs({"open", "open|filtered"}) do
    for _, p in ipairs({"tcp","udp"}) do
      local port = nil
      while( true ) do
        port = nmap.get_ports(host, port, p, s)
        if ( not(port) ) then break  end
        local key = names and port.service or port.number
        if key == "unknown" then
          -- If they are sorting by name, don't lump all "unknown" together.
          key = port.number
        end
        db[p][key] = db[p][key] or {}
        table.insert(db[p][key], host.ip)
      end
    end
  end
end

local commasep = {
  __tostring = function (t)
    return table.concat(t, ", ")
  end
}

postaction = function()
  local db = nmap.registry[SCRIPT_NAME]
  if ( db == nil ) then
    return nil
  end

  local results
  local mode = stdnse.get_script_args("reverse-index.mode") or "horizontal"

  local results = stdnse.output_table()
  for proto, ports in pairs(db) do
    local portnumbers = stdnse.keys(ports)
    table.sort(portnumbers)
    for _, port in ipairs(portnumbers) do
      local result_entries = ports[port]
      ipOps.ip_sort(result_entries)
      if mode == 'horizontal' then
        setmetatable(result_entries, commasep)
      end
      results[("%s/%s"):format(port, proto)] = result_entries
    end
  end

  return results
end

local Actions = {
  hostrule = hostaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
