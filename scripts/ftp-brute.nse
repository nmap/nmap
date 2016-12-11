local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Performs brute force password auditing against FTP servers.

Based on old ftp-brute.nse script by Diman Todorov, Vlatko Kosturjak and Ron Bowes.

06.08.16 - Modified by Sergey Khegay to support new brute.lua adaptability mechanism.
]]

---
-- @usage
-- nmap --script ftp-brute -p 21 <host>
--
-- This script uses brute library to perform password
-- guessing.
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | my-ftp-brute:
-- |   Accounts
-- |     root:root - Valid credentials
-- |   Statistics
-- |_    Performed 510 guesses in 610 seconds, average tps: 0
--
-- @args ftp-brute.timeout the amount of time to wait for a response on the socket.
--       Lowering this value may result in a higher throughput for servers
--       having a delayed response on incorrect login attempts. (default: 5s)

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
    local status, err = self.socket:connect(self.host, self.port)
    self.socket:set_timeout(arg_timeout)
    if(not(status)) then
      return false, brute.Error:new( "Couldn't connect to host: " .. err )
    end
    return true
  end,

  login = function (self, user, pass)
    local status, err
    local res = ""

    status, err = self.socket:send("USER " .. user .. "\r\n")
    if(not(status)) then
      return false, brute.Error:new("Couldn't send login: " .. err)
    end

    status, err = self.socket:send("PASS " .. pass .. "\r\n")
    if(not(status)) then
      return false, brute.Error:new("Couldn't send login: " .. err)
    end

    -- Create a buffer and receive the first line
    local buffer = stdnse.make_buffer(self.socket, "\r?\n")
    local line = buffer()

    -- Loop over the lines
    while(line)do
      stdnse.debug1("Received: %s", line)
      if(string.match(line, "^230")) then
        stdnse.debug1("Successful login: %s/%s", user, pass)
        return true, creds.Account:new( user, pass, creds.State.VALID)
      elseif(string.match(line, "^530")) then
        return false, brute.Error:new( "Incorrect password" )
      elseif(string.match(line, "^421")) then
        local err = brute.Error:new("Too many connections")
        err:setReduce(true)
        return false, err
      elseif(string.match(line, "^220")) then
      elseif(string.match(line, "^331")) then
      else
        stdnse.debug1("WARNING: Unhandled response: %s", line)
        local err = brute.Error:new("Unhandled response")
        err:setRetry(true)
        return false, err
      end

      line = buffer()
    end


    return false, brute.Error:new("Login didn't return a proper response")
  end,

  disconnect = function( self )
    self.socket:close()
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
