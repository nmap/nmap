local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description=[[
Performs brute force password auditing against the classic UNIX rexec (remote exec) service.
]]

---
-- @usage
-- nmap -p 512 --script rexec-brute <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 512/tcp open  exec
-- | rexec-brute:
-- |   Accounts
-- |     nmap:test - Valid credentials
-- |   Statistics
-- |_    Performed 16 guesses in 7 seconds, average tps: 2
--
-- @args rexec-brute.timeout  socket timeout for connecting to rexec (default 10s)

-- Version 0.1
-- Created 11/02/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(512, "exec", "tcp")


Driver = {

  -- creates a new Driver instance
  -- @param host table as received by the action function
  -- @param port table as received by the action function
  -- @return o instance of Driver
  new = function(self, host, port, options)
    local o = { host = host, port = port, timeout = options.timeout }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.timeout)
    local status, err = self.socket:connect(self.host, self.port)
    if ( not(status) ) then
      local err = brute.Error:new("Connection failed")
      err:setRetry( true )
      return false, err
    end
    return true
  end,

  login = function(self, username, password)
    local cmd = "id"
    local data = ("\0%s\0%s\0%s\0"):format(username, password, cmd)

    local status, err = self.socket:send(data)
    if ( not(status) ) then
      local err = brute.Error:new("Send failed")
      err:setRetry( true )
      return false, err
    end

    local response
    status, response = self.socket:receive()
    if ( status ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function(self)
    self.socket:close()
  end,

}


local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 10) * 1000

action = function(host, port)
  local options = {
    timeout = arg_timeout
  }

  local engine = brute.Engine:new(Driver, host, port, options)
  engine.options.script_name = SCRIPT_NAME
  local status, result = engine:start()
  return result
end
