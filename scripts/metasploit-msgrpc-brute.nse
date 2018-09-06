local brute = require "brute"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local creds = require "creds"

description = [[
Performs brute force username and password auditing against
Metasploit msgrpc interface.

]]

---
-- @usage
-- nmap --script metasploit-msgrpc-brute -p 55553 <host>
--
-- This script uses brute library to perform password
-- guessing against Metasploit's msgrpc interface.
--
--
-- @output
-- PORT      STATE SERVICE REASON
-- 55553/tcp open  unknown syn-ack
-- | metasploit-msgrpc-brute:
-- |   Accounts
-- |     root:root - Valid credentials
-- |   Statistics
-- |_    Performed 10 guesses in 10 seconds, average tps: 1



author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(55553,"metasploit-msgrpc")


-- returns a "prefix" that msgpack uses for strings
local get_prefix = function(data)
  if #data <= 31 then
    return string.pack("B", 0xa0 + #data)
  else
    return "\xda"  .. string.pack(">I2", #data)
  end
end

-- simple function that implements basic msgpack encoding we need for this script
-- see http://wiki.msgpack.org/display/MSGPACK/Format+specification for more
local encode = function(username, password)
  return "\x93\xaaauth.login" .. get_prefix(username) .. username .. get_prefix(password) .. password
end

Driver = {

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  -- as we are using http methods, no need for connect and disconnect
  -- this might cause a problem as in other scripts that don't have explicit connect
  -- as there is no way to "reserve" a socket
  connect = function( self )
    return true
  end,

  login = function (self, user, pass)
    local data
    local options = {
      header = {
        ["Content-Type"] = "binary/message-pack"
      }
    }
    stdnse.debug1( "Trying %s/%s ...", user, pass )
    data = http.post(self.host,self.port, "/api/",options, nil , encode(user,pass))
    if data and data.status and tostring( data.status ):match( "200" )  then
      if string.find(data.body,"success") then
        return true, creds.Account:new( user, pass, creds.State.VALID)
      else
        return false,  brute.Error:new( "Incorrect username or password" )
      end
    end
    local err = brute.Error:new("Login didn't return a proper response")
    err:setRetry( true )
    return false, err
  end,

  disconnect = function( self )
    return true
  end
}

action = function( host, port )

  local status, result
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.max_threads = 3
  engine.max_retries = 10
  status, result = engine:start()

  return result
end
