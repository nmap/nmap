local bitcoin = require "bitcoin"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Extracts version and node information from a Bitcoin server
]]

---
-- @usage
-- nmap -p 8333 --script bitcoin-info <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 8333/tcp open  unknown
-- | bitcoin-info:
-- |   Timestamp: Wed Nov  9 19:47:23 2011
-- |   Network: main
-- |   Version: 0.4.0
-- |   Node Id: DD5DFCBAAD0F882D
-- |_  Lastblock: 152589
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

--
-- Version 0.1
--
-- Created 11/09/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--


portrule = shortport.port_or_service(8333, "bitcoin", "tcp" )

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local NETWORK = {
    [3652501241] = "main",
    [3669344250] = "testnet"
  }

  local bcoin = bitcoin.Helper:new(host, port, { timeout = 10000 })
  local status = bcoin:connect()

  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, ver = bcoin:exchVersion()
  if ( not(status) ) then
    return fail("Failed to extract version information")
  end
  bcoin:close()

  local result = {}
  table.insert(result, ("Timestamp: %s"):format(stdnse.format_timestamp(ver.timestamp)))
  table.insert(result, ("Network: %s"):format(NETWORK[ver.magic]))
  table.insert(result, ("Version: %s"):format(ver.ver))
  table.insert(result, ("Node Id: %s"):format(ver.nodeid))
  table.insert(result, ("Lastblock: %s"):format(ver.lastblock))

  return stdnse.format_output(true, result)
end
