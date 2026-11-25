local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local mongodb = stdnse.silent_require "mongodb"

description = [[
Performs brute force password auditing against the MongoDB database.
]]

---
-- @usage
-- nmap -p 27017 <ip> --script mongodb-brute
--
-- @args mongodb-brute.db Database against which to check. Default: admin
--
-- @output
-- PORT      STATE SERVICE
-- 27017/tcp open  mongodb
-- | mongodb-brute:
-- |   Accounts
-- |     root:Password1 - Valid credentials
-- |   Statistics
-- |_    Performed 3542 guesses in 9 seconds, average tps: 393
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

local arg_db = stdnse.get_script_args(SCRIPT_NAME .. ".db") or "admin"

portrule = shortport.port_or_service({27017}, {"mongodb", "mongod"})

Driver = {

  new = function(self, host, port, options)
    local o = { host = host, port = port, sock = brute.new_socket(),
      proto = options and options.mongodb_proto or "tcp" }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    return self.sock:connect(self.host, self.port, self.proto)
  end,

  login = function(self, username, password)
    local status, resp = mongodb.login(self.sock, arg_db, username, password)
    if ( status ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    elseif ( resp ~= "Authentication failed" ) then
      local err = brute.Error:new( resp )
      err:setRetry( true )
      return false, err
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function(self)
    return self.sock:close()
  end,

}

local function needsAuth(host, port, proto)
  local socket = nmap.new_socket()
  local status, result = socket:connect(host, port, proto)
  if ( not(status) ) then
    return false, "Failed to connect to server"
  end

  local packet
  status, packet = mongodb.listDbQuery()
  if ( not(status) ) then
    return false, result
  end

  --- Send packet
  status, result = mongodb.query(socket, packet)
  if ( not(status) ) then
    return false, result
  end

  socket:close()
  if ( status and result.errmsg ) then
    return true
  end
  return false
end

action = function(host, port)

  -- MongoDB servers speak TLS from the first byte; there is no in-band
  -- STARTTLS-style upgrade. Discover the protocol via comm.tryssl and
  -- reconnect using it afterwards.
  local status, packet = mongodb.listDbQuery()
  if ( not(status) ) then return packet end

  local _, _, proto = comm.tryssl(host, port, packet, { timeout = 5000 })
  if proto ~= "tcp" and proto ~= "ssl" then
    return "Failed to determine whether the server uses TLS or plaintext"
  end

  if proto == "ssl" and port.version then
    port.version.service_tunnel = "ssl"
    nmap.set_port_version(host, port)
  end

  if ( not(needsAuth(host, port, proto)) ) then
    return "No authentication needed"
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.options.mongodb_proto = proto
  local status, result = engine:start()

  return result
end
