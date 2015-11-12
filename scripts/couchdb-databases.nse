local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Gets database tables from a CouchDB database.

For more info about the CouchDB HTTP API, see
http://wiki.apache.org/couchdb/HTTP_database_API.
]]

---
-- @usage
-- nmap -p 5984 --script "couchdb-databases.nse" <host>
-- @output
-- PORT      STATE SERVICE REASON
-- 5984/tcp open  unknown syn-ack
-- | couchdb-databases:
-- |   1 = test_suite_db
-- |   2 = test_suite_db_a
-- |   3 = test_suite_db/with_slashes
-- |   4 = moneyz
-- |   5 = creditcards
-- |   6 = test_suite_users
-- |_  7 = test_suite_db_b

-- version 0.2
-- Created 01/12/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>

-- TODO : Authentication not implemented

author = "Martin Holst Swende"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({5984})
-- Some lazy shortcuts
local dbg = stdnse.debug1

local DISCARD = {}
--- Removes uninteresting data from the table
-- uses the DISCARD table above to see what
-- keys should be omitted from the results
-- @param data a table containing data
--@return another table containing data, with some keys removed
local function queryResultToTable(data)
  local result = {}
  for k,v in pairs(data) do
    dbg("(%s,%s)",k,tostring(v))
    if DISCARD[k] ~= 1 then
      if type(v) == 'table' then
        table.insert(result,k)
        table.insert(result,queryResultToTable(v))
      else
        table.insert(result,(("%s = %s"):format(tostring(k), tostring(v))))
      end
    end
  end
  return result
end

action = function(host, port)
  local data, result, err
  dbg("Requesting all databases")
  data = http.get( host, port, '/_all_dbs' )

  -- check that body was received
  if not data.body or data.body == "" then
    local msg = ("%s did not respond with any data."):format(host.targetname or host.ip )
    dbg( msg )
    return  msg
  end

  -- The html body should look like this :
  -- ["somedatabase", "anotherdatabase"]

  local status, result = json.parse(data.body)
  if not status then
    dbg(result)
    return result
  end

  -- Here we know it is a couchdb
  port.version.name ='httpd'
  port.version.product='Apache CouchDB'
  nmap.set_port_version(host,port)

  -- We have a valid table in result containing the parsed json
  -- now, get all the interesting bits

  result = queryResultToTable(result)

  return stdnse.format_output(true, result )
end
