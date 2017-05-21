local coroutine = require "coroutine"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local wsdd = require "wsdd"

description = [[
Uses a multicast query to discover devices supporting the Web Services
Dynamic Discovery (WS-Discovery) protocol. It also attempts to locate
any published Windows Communication Framework (WCF) web services (.NET
4.0 or later).
]]

---
-- @usage
-- sudo ./nmap --script broadcast-wsdd-discover
--
-- @output
-- | broadcast-wsdd-discover:
-- |   Devices
-- |     1.2.3.116
-- |         Message id: 9ea97e41-e874-faa7-fe28-deadbeefceb3
-- |         Address: http://1.2.3.116:50000
-- |         Type: Device wprt:PrintDeviceType
-- |     1.2.3.131
-- |         Message id: 4d971368-291c-1218-30f1-deadbeefceb3
-- |         Address: http://1.2.3.131:5357/deadbeef-ea5c-4b9a-a68d-deadbeefceb3/
-- |         Type: Device pub:Computer
-- |     1.2.3.110
-- |         Message id: f5a25a38-d61c-49e5-96c4-deadbeefceb3
-- |         Address: http://1.2.3.110:5357/deadbeef-469b-4da4-b413-deadbeefee90/
-- |         Type: Device pub:Computer
-- |   WCF Services
-- |     1.2.3.131
-- |         Message id: c1767df8-43e5-4440-9e26--deadbeefceb3
-- |_        Address: http://win-7:8090/discovery/scenarios/service2/deadbeef-3382-4668-86e7-deadbeefb935/
--
--

--
-- Version 0.1
-- Created 10/31/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

-- function used for running several discovery threads in parallel
--
-- @param funcname string containing the name of the function to run
--        the name should be one of the discovery functions in wsdd.Helper
-- @param result table into which the results are stored
discoverThread = function( funcname, results )
  -- calculates a timeout based on the timing template (default: 5s)
  local timeout = ( 20000 / ( nmap.timing_level() + 1 ) )
  local condvar = nmap.condvar( results )
  local helper = wsdd.Helper:new()
  helper:setMulticast(true)
  helper:setTimeout(timeout)

  local status, result = helper[funcname](helper)
  if ( status ) then table.insert(results, result) end
  condvar("broadcast")
end

local function sortfunc(a,b)
  if ( a and b and a.name and b.name ) and ( a.name < b.name ) then
    return true
  end
  return false
end

action = function()

  local threads, results = {}, {}
  local condvar = nmap.condvar( results )

  -- Attempt to discover both devices and WCF web services
  for _, f in ipairs( {"discoverDevices", "discoverWCFServices"} ) do
    threads[stdnse.new_thread( discoverThread, f, results )] = true
  end

  local done
  -- wait for all threads to finish
  while( not(done) ) do
    done = true
    for thread in pairs(threads) do
      if (coroutine.status(thread) ~= "dead") then done = false end
    end
    if ( not(done) ) then
      condvar("wait")
    end
  end

  if ( results ) then
    table.sort( results, sortfunc )
    return stdnse.format_output(true, results)
  end
end
