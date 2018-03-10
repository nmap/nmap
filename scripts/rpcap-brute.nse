local brute = require "brute"
local creds = require "creds"
local rpcap = require "rpcap"
local shortport = require "shortport"

description = [[
Performs brute force password auditing against the WinPcap Remote Capture
Daemon (rpcap).
]]

---
-- @usage
-- nmap -p 2002 <ip> --script rpcap-brute
--
-- @output
-- PORT     STATE SERVICE REASON
-- 2002/tcp open  globe   syn-ack
-- | rpcap-brute:
-- |   Accounts
-- |     monkey:Password1 - Valid credentials
-- |   Statistics
-- |_    Performed 3540 guesses in 3 seconds, average tps: 1180
--
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(2002, "rpcap", "tcp")

Driver = {

  new = function(self, host, port)
    local o = { helper = rpcap.Helper:new(host, port, brute.new_socket()) }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    return self.helper:connect()
  end,

  login = function(self, username, password)
    local status, resp = self.helper:login(username, password)
    if ( status ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function(self)
    return self.helper:close()
  end,

}

local function validateAuth(host, port)
  local helper = rpcap.Helper:new(host, port)
  local status, result = helper:connect()
  if ( not(status) ) then
    return false, result
  end
  status, result = helper:login()
  helper:close()

  if ( status ) then
    return false, "Authentication not required"
  elseif ( not(status) and
    "Authentication failed; NULL authentication not permitted." == result ) then
    return true
  end
  return status, result
end

action = function(host, port)

  local status, result = validateAuth(host, port)
  if ( not(status) ) then
    return result
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  status, result = engine:start()

  return result
end


