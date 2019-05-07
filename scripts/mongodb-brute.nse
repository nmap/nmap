local brute = require "brute"
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
    local o = { host = host, port = port, sock = brute.new_socket() }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    return self.sock:connect(self.host, self.port)
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

local function needsAuth(host, port)
  local socket = nmap.new_socket()
  local status, result = socket:connect(host, port)
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

  if ( not(needsAuth(host, port)) ) then
    return "No authentication needed"
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  local status, result = engine:start()

  return result
end
