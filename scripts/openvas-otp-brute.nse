local brute = require "brute"
local creds = require "creds"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

description=[[
Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1.0 protocol.
]]

---
-- @output
-- PORT     STATE SERVICE    REASON  VERSION
-- 9391/tcp open  ssl/openvas syn-ack
-- | openvas-otp-brute:
-- |   Accounts
-- |     openvas:openvas - Valid credentials
-- |   Statistics
-- |_    Performed 4 guesses in 4 seconds, average tps: 1
--
-- @args openvas-otp-brute.threads sets the number of threads. Default: 4

author = "Vlatko Kosturjak"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


portrule = shortport.port_or_service({9390,9391}, "openvas", "tcp")

Driver =
{
  new = function (self, host, port)
    local o = { host = host, port = port }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  connect = function ( self )
    self.socket = brute.new_socket()
    if ( not(self.socket:connect(self.host, self.port, "ssl")) ) then
      return false
    end
    return true
  end,

  login = function( self, username, password )
    local status, err = self.socket:send("< OTP/1.0 >\n")

    if ( not ( status ) ) then
      local err = brute.Error:new( "Unable to send handshake" )
      err:setAbort(true)
      return false, err
    end

    local response
    status, response = self.socket:receive_buf(match.pattern_limit("\r?\n", 2048), false)
    if ( not(status) or response ~= "< OTP/1.0 >" ) then
      local err = brute.Error:new( "Bad handshake from server: "..response )
      err:setAbort(true)
      return false, err
    end

    status, err = self.socket:send(username.."\n")
    if ( not(status) ) then
      local err = brute.Error:new( "Couldn't send user: "..username )
      err:setAbort( true )
      return false, err
    end

    status, err = self.socket:send(password.."\n")
    if ( not(status) ) then
      local err = brute.Error:new( "Couldn't send password: "..password )
      err:setAbort( true )
      return false, err
    end

    -- Create a buffer and receive the first line
    local line
    status, line = self.socket:receive_buf(match.pattern_limit("\r?\n", 2048), false)

    if (line == nil or string.match(line,"Bad login")) then
      stdnse.debug2("Bad login: %s/%s", username, password)
      return false, brute.Error:new( "Bad login" )
    elseif (string.match(line,"SERVER <|>")) then

      stdnse.debug1("Good login: %s/%s", username, password)
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    stdnse.debug1("WARNING: Unhandled response: %s", line)
    return false, brute.Error:new( "unhandled response" )
  end,

  disconnect = function( self )
    self.socket:close()
  end,
}

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine:setMaxThreads(1)
  engine.options.script_name = SCRIPT_NAME
  local status, result = engine:start()
  return result
end

