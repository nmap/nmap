local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local target = require "target"
local os = require "os"
local table = require "table"

description = [[
Discovers HID devices on a LAN by sending a discoveryd network broadcast probe.

For more information about HID discoveryd, see:
* http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html
* https://github.com/coldfusion39/VertXploit
]]

---
-- @usage nmap --script broadcast-hid-discoveryd
-- @usage nmap --script broadcast-hid-discoveryd --script-args timeout=15s
--
-- @output
-- Pre-scan script results:
-- | broadcast-hid-discoveryd:
-- |   MAC: 00:06:8E:00:00:00; Name: NoEntry; IP Address: 10.123.123.1; Model: EH400; Version: 2.3.1.603 (04/23/2012)
-- |   MAC: 00:06:8E:FF:FF:FF; Name: NoExit; IP Address: 10.123.123.123; Model: EH400; Version: 2.3.1.603 (04/23/2012)
-- |_  Use --script-args=newtargets to add the results as targets
--
-- @args broadcast-hid-discoveryd.address
--       address to which the probe packet is sent. (default: 255.255.255.255)
-- @args broadcast-hid-discoveryd.timeout
--       socket timeout (default: 5s)
---

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "broadcast", "safe"}

prerule = function() return ( nmap.address_family() == "inet") end

local arg_address = stdnse.get_script_args(SCRIPT_NAME .. ".address")
local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

action = function()

  local host = { ip = arg_address or "255.255.255.255" }
  local port = { number = 4070, protocol = "udp" }
  local socket = nmap.new_socket("udp")

  socket:set_timeout(500)

  -- send two packets, just in case
  for i=1,2 do
    local status = socket:sendto(host, port, "discover;013;")
    if ( not(status) ) then
      return stdnse.format_output(false, "Failed to send broadcast probe")
    end
  end

  local timeout = tonumber(arg_timeout) or ( 20 / ( nmap.timing_level() + 1 ) )
  local results = {}
  local stime = os.time()

  -- listen until timeout
  repeat
    local status, data = socket:receive()
    if ( status ) then
      local hid_pkt = data:match("^discovered;.*$")
      if ( hid_pkt ) then
        local status, _, _, rhost, _ = socket:get_info()
        local hid_data = stringaux.strsplit(";", hid_pkt)
        if #hid_data == 10 and hid_data[1] == 'discovered' and tonumber(hid_data[2]) == string.len(hid_pkt) then
          stdnse.print_debug(2, "Received HID discoveryd response from %s (%s bytes)", rhost, string.len(hid_pkt))
          local str = ("MAC: %s; Name: %s; IP Address: %s; Model: %s; Version: %s (%s)"):format(
            hid_data[3], hid_data[4], hid_data[5], hid_data[7], hid_data[8], hid_data[9])
          table.insert( results, str )
          if target.ALLOW_NEW_TARGETS then
            target.add(hid_data[5])
          end
        end
      end
    end
  until( os.time() - stime > timeout )
  socket:close()

  local output = stdnse.output_table()
  if #results > 0 then
    -- remove duplicates
    local hash = {}
    for _,v in ipairs(results) do
      if (not hash[v]) then
        table.insert( output, v )
        hash[v] = true
      end
    end
    if not target.ALLOW_NEW_TARGETS then
      output[#output + 1] = "Use --script-args=newtargets to add the results as targets"
    end
    return output
  end
end
