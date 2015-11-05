local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Sends a special broadcast probe to discover PC-Anywhere hosts running on a LAN.
]]

---
-- @usage
-- nmap --script broadcast-pc-anywhere
--
-- @output
-- Pre-scan script results:
-- | broadcast-pc-anywhere:
-- |_  10.0.200.113 - WIN2K3SRV-1
--
-- @args broadcast-pc-anywhere.timeout specifies the amount of seconds to sniff
--       the network interface. (default varies according to timing. -T3 = 5s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "broadcast", "safe" }

local TIMEOUT = stdnse.parse_timespec(stdnse.get_script_args("broadcast-pc-anywhere.timeout"))

prerule = function() return ( nmap.address_family() == "inet") end

action = function()


  local host = { ip = "255.255.255.255" }
  local port = { number = 5632, protocol = "udp" }

  local socket = nmap.new_socket("udp")
  socket:set_timeout(500)

  for i=1,2 do
    local status = socket:sendto(host, port, "NQ")
    if ( not(status) ) then
      return stdnse.format_output(false, "Failed to send broadcast request")
    end
  end

  local timeout = TIMEOUT or ( 20 / ( nmap.timing_level() + 1 ) )
  local responses = {}
  local stime = os.time()

  repeat
    local status, data = socket:receive()
    if ( status ) then
      local srvname = data:match("^NR([^_]*)_*AHM_3___\0$")
      if ( srvname ) then
        local status, _, _, rhost, _ = socket:get_info()
        if ( not(status) ) then
          socket:close()
          return false, "Failed to get socket information"
        end
        -- avoid duplicates
        responses[rhost] = srvname
      end
    end
  until( os.time() - stime > timeout )
  socket:close()

  local result = {}
  for ip, name in pairs(responses) do
    table.insert(result, ("%s - %s"):format(ip,name))
  end
  return stdnse.format_output(true, result)
end
