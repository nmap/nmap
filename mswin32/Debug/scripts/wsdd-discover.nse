local coroutine = require "coroutine"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local wsdd = require "wsdd"

description = [[
Retrieves and displays information from devices supporting the Web
Services Dynamic Discovery (WS-Discovery) protocol. It also attempts
to locate any published Windows Communication Framework (WCF) web
services (.NET 4.0 or later).
]]

---
-- @usage
-- sudo ./nmap --script wsdd-discover
--
-- @output
-- PORT     STATE         SERVICE
-- 3702/udp open|filtered unknown
-- | wsdd-discover:
-- |   Devices
-- |     Message id: 39a2b7f2-fdbd-690c-c7c9-deadbeefceb3
-- |     Address: http://10.0.200.116:50000
-- |_    Type: Device wprt:PrintDeviceType
--
--

--
-- Version 0.1
-- Created 10/31/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}


portrule = shortport.portnumber(3702, "udp", {"open", "open|filtered"})

-- function used for running several discovery threads in parallel
--
-- @param funcname string containing the name of the function to run
--        the name should be one of the discovery functions in wsdd.Helper
-- @param result table into which the results are stored
discoverThread = function( funcname, host, port, results )
  -- calculates a timeout based on the timing template (default: 5s)
  local timeout = ( 20000 / ( nmap.timing_level() + 1 ) )
  local condvar = nmap.condvar( results )
  local helper = wsdd.Helper:new(host, port)
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

action = function(host, port)

  local threads, results = {}, {}
  local condvar = nmap.condvar( results )

  -- Attempt to discover both devices and WCF web services
  for _, f in ipairs( {"discoverDevices", "discoverWCFServices"} ) do
    threads[stdnse.new_thread( discoverThread, f, host, port, results )] = true
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
