local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves cluster and store information from the Voldemort distributed key-value store using the Voldemort Native Protocol.
]]

---
-- @usage
-- nmap -p 6666 --script voldemort-info <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 6666/tcp open  irc
-- | voldemort-info:
-- |   Cluster
-- |     Name: mycluster
-- |     Id: 0
-- |     Host: localhost
-- |     HTTP Port: 8081
-- |     TCP Port: 6666
-- |     Admin Port: 6667
-- |     Partitions: 0, 1
-- |   Stores
-- |     test
-- |       Persistence: bdb
-- |       Description: Test store
-- |       Owners: harry@hogwarts.edu, hermoine@hogwarts.edu
-- |       Routing strategy: consistent-routing
-- |       Routing: client
-- |     wordcounts
-- |       Persistence: read-only
-- |       Routing strategy: consistent-routing
-- |_      Routing: client
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(6666, "vp3", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

-- Connect to the server and make sure it supports the vp3 protocol
-- @param host table as received by the action method
-- @param port table as received by the action method
-- @return status true on success, false on failure
-- @return socket connected to the server
local function connect(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host, port)
  if ( not(status) ) then
    return false, "Failed to connect to server"
  end

  status, err = socket:send("vp3")
  if ( not(status) ) then
    return false, "Failed to send request to server"
  end

  local response
  status, response = socket:receive(2)
  if ( not(status) ) then
    return false, "Failed to receive response from server"
  elseif( response ~= "ok" ) then
    return false, "Unsupported protocol"
  end
  return true, socket
end

-- Get Voldemort metadata
-- @param socket connected to the server
-- @param file the xml file to retrieve
-- @return status true on success false on failure
-- @return data string as received from the server
local function getMetadata(socket, file)

  local req = bin.pack(">HCzIcz", "0100", #("metadata"), "metadata", 0, #file, file)
  local status, err = socket:send(req)
  if ( not(status) ) then
    return false, "Failed to send request to server"
  end
  local status, data = socket:receive(8)
  if ( not(status) ) then
    return false, "Failed to receive response from server"
  end
  local _, len = bin.unpack(">S", data, 9)
  while( #data < len - 2 ) do
    local status, tmp = socket:receive(len - 2 - #data)
    if ( not(status) ) then
      return false, "Failed to receive response from server"
    end
    data = data .. tmp
  end
  return true, data
end


action = function(host, port)

  -- table of variables to query the server
  local vars = {
    ["cluster"] = {
      { key = "Name", match = "<cluster>.-<name>(.-)</name>" },
      { key = "Id", match = "<cluster>.-<server>.-<id>(%d-)</id>.-</server>" },
      { key = "Host",  match = "<cluster>.-<server>.-<host>(%w-)</host>.-</server>" },
      { key = "HTTP Port", match = "<cluster>.-<server>.-<http%-port>(%d-)</http%-port>.-</server>" },
      { key = "TCP Port", match = "<cluster>.-<server>.-<socket%-port>(%d-)</socket%-port>.-</server>" },
      { key = "Admin Port", match = "<cluster>.-<server>.-<admin%-port>(%d-)</admin%-port>.-</server>" },
      { key = "Partitions", match = "<cluster>.-<server>.-<partitions>([%d%s,]*)</partitions>.-</server>" },
    },
    ["store"] = {
      { key = "Persistence", match = "<store>.-<persistence>(.-)</persistence>" },
      { key = "Description", match = "<store>.-<description>(.-)</description>" },
      { key = "Owners", match = "<store>.-<owners>(.-)</owners>" },
      { key = "Routing strategy", match = "<store>.-<routing%-strategy>(.-)</routing%-strategy>" },
      { key = "Routing", match = "<store>.-<routing>(.-)</routing>" },
    },
  }

  -- connect to the server
  local status, socket = connect(host, port)
  if ( not(status) ) then
    return fail(socket)
  end

  -- get the cluster meta data
  local status, response = getMetadata(socket, "cluster.xml")
  if ( not(status) or not(response:match("<cluster>.*</cluster>")) ) then
    return
  end

  -- Get the cluster details
  local cluster_tbl = { name = "Cluster" }
  for _, item in ipairs(vars["cluster"]) do
    local val = response:match(item.match)
    if ( val ) then
      table.insert(cluster_tbl, ("%s: %s"):format(item.key, val))
    end
  end

  -- get the stores meta data
  local status, response = getMetadata(socket, "stores.xml")
  if ( not(status) or not(response:match("<stores>.-</stores>")) ) then
    return
  end

  local result, stores = {}, { name = "Stores" }
  table.insert(result, cluster_tbl)

  -- iterate over store items
  for store in response:gmatch("<store>.-</store>") do
    local name = store:match("<store>.-<name>(.-)</name>")
    local store_tbl = { name = name or "unknown" }

    for _, item in ipairs(vars["store"]) do
      local val = store:match(item.match)
      if ( val ) then
        table.insert(store_tbl, ("%s: %s"):format(item.key, val))
      end
    end
    table.insert(stores, store_tbl)
  end
  table.insert(result, stores)
  return stdnse.format_output(true, result)
end
