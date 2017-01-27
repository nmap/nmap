local base64 = require "base64"
local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Performs brute force password auditing against an iPhoto Library.
]]


---
-- @usage
-- nmap --script dpap-brute -p 8770 <host>
--
-- @output
-- 8770/tcp open  apple-iphoto syn-ack
-- | dpap-brute:
-- |   Accounts
-- |     secret => Login correct
-- |   Statistics
-- |_    Perfomed 5007 guesses in 6 seconds, average tps: 834
--
--
-- Version 0.1
-- Created 24/01/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(8770, "apple-iphoto")

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
    self.socket = nmap.new_socket()
    self.socket:set_timeout(5000)
    return self.socket:connect(self.host, self.port, "tcp")
  end,

  login = function( self, username, password )
    local data = "GET dpap://%s:%d/login HTTP/1.1\r\n" ..
      "User-Agent: iPhoto/9.1.1  (Macintosh; N; PPC)\r\n" ..
      "Host: %s\r\n" ..
      "Authorization: Basic %s\r\n" ..
      "Client-DPAP-Version: 1.1\r\n" ..
      "\r\n\r\n"

    local c = base64.enc("nmap:" .. password)
    data = data:format( self.host.ip, self.port.number, self.host.ip, c )

    local status = self.socket:send( data )
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send data to DPAP server" )
      err:setRetry( true )
      return false, err
    end

    status, data = self.socket:receive()
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to receive data from DPAP server" )
      err:setRetry( true )
      return false, err
    end

    if ( data:match("^HTTP/1.1 200 OK") ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    self.socket:close()
  end,

}

local function checkEmptyPassword(host, port)
  local d = Driver:new(host, port)
  local status = d:connect()

  if ( not(status) ) then
    return false
  end

  status = d:login("", "")
  d:disconnect()

  return status
end


action = function(host, port)

  if ( checkEmptyPassword(host, port) ) then
    return "Library has no password"
  end

  local status, result
  local engine = brute.Engine:new(Driver, host, port )

  engine.options.firstonly = true
  engine.options:setOption( "passonly", true )
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()

  return result
end





