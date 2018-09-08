local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local os = require "os"
local table = require "table"
local rand = require "rand"

description = [[
Discovers Jenkins servers on a LAN by sending a discovery broadcast probe.

For more information about Jenkins auto discovery, see:
* https://wiki.jenkins.io/display/JENKINS/Auto-discovering+Jenkins+on+the+network
]]

---
-- @usage nmap --script broadcast-jenkins-discover
-- @usage nmap --script broadcast-jenkins-discover --script-args timeout=15s
--
-- @output
-- Pre-scan script results:
-- | broadcast-jenkins:
-- |   Version: 2.60.2; Server ID: d5e31b7a9d69cf3c89cc799c23199760; Slave Port: 35928
-- |_  Version: 2.60.2; Server ID: b98e8e1b862c3eecb14e8be0028cf4ee; Slave Port: 45435
--
-- @args broadcast-jenkins.address
--       address to which the probe packet is sent. (default: 255.255.255.255)
-- @args broadcast-jenkins.timeout
--       socket timeout (default: 5s)
---

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "broadcast", "safe"}

prerule = function() return ( nmap.address_family() == "inet") end

local arg_address = stdnse.get_script_args(SCRIPT_NAME .. ".address")
local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

action = function()

  local host = { ip = arg_address or "255.255.255.255" } -- broadcast
  -- local host = { ip = arg_address or "239.77.124.213" } -- multicast
  local port = { number = 33848, protocol = "udp" }
  local socket = nmap.new_socket("udp")

  socket:set_timeout(500)

  -- send two packets, just in case
  local probe = rand.random_string(10)
  for i=1,2 do
    local status = socket:sendto(host, port, probe)
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
      local jenkins_pkt = data:match("^<hudson>(.+)</hudson>")
      if ( jenkins_pkt ) then
        local status, _, _, rhost, _ = socket:get_info()
        local version = jenkins_pkt:match("<version>(.*)</version>")
        local server_id = jenkins_pkt:match("<server%-id>(.*)</server%-id>")
        local slave_port = jenkins_pkt:match("<slave%-port>(.*)</slave%-port>")
        if version and server_id and slave_port then
          stdnse.print_debug(2, "Received Jenkins discovery response from %s (%s bytes)", rhost, string.len(jenkins_pkt))
          local str = ("Version: %s; Server ID: %s; Slave Port: %s"):format(version, server_id, slave_port)
          table.insert( results, str )
        end
      end
    end
  until( os.time() - stime > timeout )
  socket:close()

  local response = stdnse.output_table()
  if #results > 0 then
    -- remove duplicates
    local hash = {}
    for _,v in ipairs(results) do
      if (not hash[v]) then
        table.insert( response, v )
        hash[v] = true
      end
    end
    return response
  end
end
