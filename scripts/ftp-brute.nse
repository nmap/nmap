local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ftp = require "ftp"

description = [[
Performs brute force password auditing against FTP servers.

Based on old ftp-brute.nse script by Diman Todorov, Vlatko Kosturjak and Ron Bowes.
]]

---
-- @see ftp-anon.nse
--
-- @usage
-- nmap --script ftp-brute -p 21 <host>
--
-- This script uses brute library to perform password
-- guessing.
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-brute:
-- |   Accounts
-- |     root:root - Valid credentials
-- |   Statistics
-- |_    Performed 510 guesses in 610 seconds, average tps: 0
--
-- @args ftp-brute.timeout the amount of time to wait for a response on the socket.
--       Lowering this value may result in a higher throughput for servers
--       having a delayed response on incorrect login attempts. (default: 5s)

-- 06.08.16 - Modified by Sergey Khegay to support new brute.lua adaptability mechanism.
author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(21, "ftp")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

Driver = {

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function( self )
    self.socket = brute.new_socket()
    -- discard buffer, we'll create a new one over the BruteSocket later
    local realsocket, code, message, buffer = ftp.connect(self.host, self.port, {request_timeout=arg_timeout})
    if not realsocket then
      return false, brute.Error:new( "Couldn't connect to host: " .. (code or message) )
    end
    self.socket.socket = realsocket
    return true
  end,

  login = function (self, user, pass)
    local buffer = stdnse.make_buffer(self.socket, "\r?\n")
    local status, code, message = ftp.auth(self.socket, buffer, user, pass)

    if not status then
      if not code then
        return false, brute.Error:new("socket error during login: " .. message)
      elseif code == 530 then
        return false, brute.Error:new( "Incorrect password" )
      elseif code == 421 then
        local err = brute.Error:new("Too many connections")
        err:setReduce(true)
        return false, err
      else
        stdnse.debug1("WARNING: Unhandled response: %d %s", code, message)
        local err = brute.Error:new("Unhandled response")
        err:setRetry(true)
        return false, err
      end
    end

    stdnse.debug1("Successful login: %s/%s", user, pass)
    return true, creds.Account:new( user, pass, creds.State.VALID)
  end,

  disconnect = function( self )
    ftp.close(self.socket)
    return true
  end
}

action = function( host, port )
  local status, result
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()
  return result
end
