local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local versant = require "versant"

description = [[
Extracts information, including file paths, version and database names from
a Versant object database.
]]

---
-- @usage
-- nmap -p 5019 <ip> --script versant-info
--
-- @output
-- PORT     STATE SERVICE REASON
-- 5019/tcp open  versant syn-ack
-- | versant-info:
-- |   Hostname: WIN-S6HA7RJFAAR
-- |   Root path: C:\Versant\8
-- |   Database path: C:\Versant\db
-- |   Library path: C:\Versant\8
-- |   Version: 8.0.2
-- |   Databases
-- |     FirstDB@WIN-S6HA7RJFAAR:5019
-- |       Created: Sat Mar 03 12:00:02 2012
-- |       Owner: Administrator
-- |       Version: 8.0.2
-- |     SecondDB@WIN-S6HA7RJFAAR:5019
-- |       Created: Sat Mar 03 03:44:10 2012
-- |       Owner: Administrator
-- |       Version: 8.0.2
-- |     ThirdDB@WIN-S6HA7RJFAAR:5019
-- |       Created: Sun Mar 04 02:20:21 2012
-- |       Owner: Administrator
-- |_      Version: 8.0.2
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5019, "versant", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local v = versant.Versant:new(host, port)
  local status = v:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, newport = v:getObePort()
  if ( not(status) ) then
    return fail("Failed to retrieve OBE port")
  end
  v:close()

  v = versant.Versant.OBE:new(host, newport)
  status = v:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local result
  status, result = v:getVODInfo()
  if ( not(status) ) then
    return fail("Failed to get VOD information")
  end
  v:close()

  local output = {}

  table.insert(output, ("Hostname: %s"):format(result.hostname))
  table.insert(output, ("Root path: %s"):format(result.root_path))
  table.insert(output, ("Database path: %s"):format(result.db_path))
  table.insert(output, ("Library path: %s"):format(result.lib_path))
  table.insert(output, ("Version: %s"):format(result.version))

  port.version.product = "Versant Database"
  port.version.name = "versant"
  nmap.set_port_version(host, port)

  -- the script may fail after this part, but we want to report at least
  -- the above information if that's the case.

  v = versant.Versant:new(host, port)
  status = v:connect()
  if ( not(status) ) then
    return stdnse.format_output(true, output)
  end

  status, result = v:getNodeInfo()
  if ( not(status) ) then
    return stdnse.format_output(true, output)
  end
  v:close()

  local databases = { name = "Databases" }

  for _, db in ipairs(result) do
    local db_tbl = { name = db.name }
    table.insert(db_tbl, ("Created: %s"):format(db.created))
    table.insert(db_tbl, ("Owner: %s"):format(db.owner))
    table.insert(db_tbl, ("Version: %s"):format(db.version))
    table.insert(databases, db_tbl)
  end

  table.insert(output, databases)
  return stdnse.format_output(true, output)
end
