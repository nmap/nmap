local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local cassandra = stdnse.silent_require "cassandra"

description = [[
Attempts to get basic info and server status from a Cassandra database.

For more information about Cassandra, see:
http://cassandra.apache.org/
]]

---
-- @usage
-- nmap -p 9160 <ip> --script=cassandra-info
--
-- @output
-- PORT     STATE SERVICE   REASON
-- 9160/tcp open  cassandra syn-ack
-- | cassandra-info:
-- |   Cluster name: Test Cluster
-- |_  Version: 19.10.0
--
-- @xmloutput
-- <elem key="Cluster name">Test Cluster</elem>
-- <elem key="Version">19.10.0</elem>

-- version 0.1
-- Created 14/09/2012 - v0.1 - created by Vlatko Kosturjak <kost@linux.hr>

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

dependencies = {"cassandra-brute"}

portrule = shortport.port_or_service({9160}, {"cassandra"})

function action(host,port)

  local socket = nmap.new_socket()
  local cassinc = 2 -- cmd/resp starts at 2

  -- set a reasonable timeout value
  socket:set_timeout(10000)
  -- do some exception  / cleanup
  local catch = function()
    socket:close()
  end

  local try = nmap.new_try(catch)

  try( socket:connect(host, port) )

  local results = stdnse.output_table()

  -- ugliness to allow creds.cassandra to work, as the port is not recognized
  -- as cassandra even when service scan was run, taken from mongodb
  local ps = port.service
  port.service = 'cassandra'
  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  for cred in c:getCredentials(creds.State.VALID + creds.State.PARAM) do
    local status, err = cassandra.login(socket, cred.user, cred.pass)
    results["Using credentials"] = cred.user.."/"..cred.pass
    if ( not(status) ) then
      return err
    end
  end
  port.service = ps

  local status, val = cassandra.describe_cluster_name(socket,cassinc)
  if (not(status)) then
    return "Error getting cluster name: " .. val
  end
  cassinc = cassinc + 1
  port.version.name ='cassandra'
  port.version.product='Cassandra'
  port.version.name_confidence = 10
  nmap.set_port_version(host,port)
  results["Cluster name"] = val

  local status, val = cassandra.describe_version(socket,cassinc)
  if (not(status)) then
    return "Error getting version: " .. val
  end
  cassinc = cassinc + 1
  port.version.product='Cassandra ('..val..')'
  nmap.set_port_version(host,port)
  results["Version"] = val

  return results
end
