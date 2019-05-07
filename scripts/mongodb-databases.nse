local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local mongodb = stdnse.silent_require "mongodb"

description = [[
Attempts to get a list of tables from a MongoDB database.
]]

---
-- @usage
-- nmap -p 27017 --script mongodb-databases <host>
-- @output
-- PORT      STATE SERVICE REASON
-- 27017/tcp open  unknown syn-ack
-- | mongodb-databases:
-- |   ok = 1
-- |   databases
-- |     1
-- |       empty = false
-- |       sizeOnDisk = 83886080
-- |       name = test
-- |     0
-- |       empty = false
-- |       sizeOnDisk = 83886080
-- |       name = httpstorage
-- |     3
-- |       empty = true
-- |       sizeOnDisk = 1
-- |       name = local
-- |     2
-- |       empty = true
-- |       sizeOnDisk = 1
-- |       name = admin
-- |_  totalSize = 167772160

-- version 0.2
-- Created 01/12/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Revised 01/03/2012 - v0.2 - added authentication support <patrik@cqure.net>

author = "Martin Holst Swende"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

dependencies = {"mongodb-brute"}


portrule = shortport.port_or_service({27017}, {"mongodb", "mongod"})

function action(host,port)

  local socket = nmap.new_socket()

  -- set a reasonable timeout value
  socket:set_timeout(10000)
  -- do some exception  / cleanup
  local catch = function()
    socket:close()
  end

  local try = nmap.new_try(catch)

  try( socket:connect(host, port) )

  -- ugliness to allow creds.mongodb to work, as the port is not recognized
  -- as mongodb, unless a service scan was run
  local ps = port.service
  port.service = 'mongodb'
  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  for cred in c:getCredentials(creds.State.VALID + creds.State.PARAM) do
    local status, err = mongodb.login(socket, "admin", cred.user, cred.pass)
    if ( not(status) ) then
      return err
    end
  end
  port.service = ps

  local req, result, packet, err, status
  --Build packet
  status, packet = mongodb.listDbQuery()
  if not status then return result end-- Error message

  --- Send packet
  status, result = mongodb.query(socket, packet)
  if not status then return result end-- Error message

  port.version.name ='mongodb'
  port.version.product='MongoDB'
  nmap.set_port_version(host,port)

  local output = mongodb.queryResultToTable(result)
  if err ~= nil then
    stdnse.log_error(err)
  end
  if result ~= nil then
    return stdnse.format_output(true, output )
  end
end
