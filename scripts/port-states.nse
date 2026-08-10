local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Prints a list of ports found in each state.

Nmap ordinarily summarizes "uninteresting" ports as "Not shown: 94 closed
ports, 4 filtered ports" but users may want to know which ports were filtered
vs which were closed. This script will expand these summaries into a list of
ports and port ranges that were found in each state.
]]

---
-- @output
-- Host script results:
-- | port-states:
-- |   tcp:
-- |     open: 22,631
-- |     closed: 7,9,13,21,23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152,9,17,19,49,53,67,69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024
-- |   udp:
-- |     open|filtered: 68,631,5353
-- |_    closed: 7,9,17,19,49,53,67,69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024
--
-- @xmloutput
-- <table key="tcp">
--   <elem key="open">22,631</elem>
--   <elem key="closed">7,9,13,21,23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152,9,17,19,49,53,67,69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024</elem>
-- </table>
-- <table key="udp">
--   <elem key="open|filtered">68,631,5353</elem>
--   <elem key="closed">7,9,17,19,49,53,67,69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,623,626,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024</elem>
-- </table>

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe" }

-- the hostrule iterates over open ports for the host
hostrule = function() return true end

local states = {
  "open",
  "open|filtered",
  "filtered",
  "unfiltered",
  "closed",
  "closed|filtered"
}
local protos = {
  "tcp", "udp", "sctp"
}

action = function(host)
  local out = stdnse.output_table()
  for _, p in ipairs(protos) do
    local proto_out = stdnse.output_table()
    for _, s in ipairs(states) do
      local t = {}
      local port = nmap.get_ports(host, nil, p, s)
      while port do
        local rstart = port.number
        local prev
        repeat
          prev = port.number
          port = nmap.get_ports(host, port, p, s)
          if not port then break end
        until (port.number > prev + 1)
        if prev > rstart then
          t[#t+1] = ("%d-%d"):format(rstart, prev)
        else
          t[#t+1] = tostring(rstart)
        end
      end
      if #t > 0 then
        proto_out[s] = table.concat(t, ",")
      end
    end
    if #proto_out > 0 then
      out[p] = proto_out
    end
  end
  if #out > 0 then
    return out
  end
end
