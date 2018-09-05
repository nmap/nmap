local datetime = require "datetime"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local target = require "target"

local bitcoin = stdnse.silent_require "bitcoin"

description = [[
Queries a Bitcoin server for a list of known Bitcoin nodes
]]

---
-- @usage
-- nmap -p 8333 --script bitcoin-getaddr <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 8333/tcp open  unknown
-- | bitcoin-getaddr:
-- |   ip                    timestamp
-- |   10.10.10.10:8333      11/09/11 17:38:00
-- |   10.10.10.11:8333      11/09/11 17:42:39
-- |   10.10.10.12:8333      11/09/11 19:34:07
-- |   10.10.10.13:8333      11/09/11 17:37:45
-- |_  10.10.10.14:8333      11/09/11 17:37:12

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

  local bcoin = bitcoin.Helper:new(host, port, { timeout = 20000 })
  local status = bcoin:connect()

  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, ver = bcoin:exchVersion()
  if ( not(status) ) then
    return fail("Failed to extract version information: " .. ver)
  end

  local status, nodes = bcoin:getNodes()
  if ( not(status) ) then
    return fail("Failed to extract address information" .. nodes)
  end
  bcoin:close()

  local response = tab.new(2)
  tab.addrow(response, "ip", "timestamp")

  for _, node in ipairs(nodes or {}) do
    if ( target.ALLOW_NEW_TARGETS ) then
      target.add(node.address.host)
    end
    tab.addrow(response, ("%s:%d"):format(node.address.host, node.address.port), datetime.format_timestamp(node.ts))
  end

  if ( #response > 1 ) then
    return stdnse.format_output(true, tab.dump(response) )
  end
end
