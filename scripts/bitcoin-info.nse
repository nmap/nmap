local os = require "os"
local datetime = require "datetime"
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
-- 8333/tcp open  bitcoin
-- | bitcoin-info:
-- |   Timestamp: 2018-03-09T06:25:49
-- |   Network: main
-- |   Version: 0.7.0
-- |   Node Id: 26855fa1ac038c12
-- |   Lastblock: 512702
-- |_  User Agent: /Satoshi:0.14.2/
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

  local request_time = os.time()
  local status, ver = bcoin:exchVersion()
  if ( not(status) ) then
    return fail("Failed to extract version information")
  end
  bcoin:close()
  datetime.record_skew(host, ver.timestamp, request_time)

  local result = stdnse.output_table()
  result["Timestamp"] = stdnse.format_timestamp(ver.timestamp)
  result["Network"] = NETWORK[ver.magic]
  result["Version"] = ver.ver
  result["Node Id"] = ver.nodeid
  result["Lastblock"] = ver.lastblock
  if ver.user_agent ~= "" then
    result["User Agent"] = ver.user_agent
  end

  return result
end
