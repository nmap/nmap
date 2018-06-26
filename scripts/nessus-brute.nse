local brute = require "brute"
local creds = require "creds"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"

description=[[
Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1.2 protocol.
]]

---
-- @usage
-- nmap --script nessus-brute -p 1241 <host>
--
-- @output
-- PORT     STATE SERVICE
-- 1241/tcp open  nessus
-- | nessus-brute:
-- |   Accounts
-- |     nessus:nessus - Valid credentials
-- |   Statistics
-- |_    Performed 35 guesses in 75 seconds, average tps: 0
--
-- This script does not appear to perform well when run using multiple threads
-- Although, it's very slow running under a single thread it does work as intended
--

--
-- Version 0.1
-- Created 22/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(1241, "nessus", "tcp")

Driver =
{

  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    self.socket = brute.new_socket()
    if ( not(self.socket:connect(self.host, self.port, "ssl")) ) then
      return false
    end
    return true
  end,

  login = function( self, username, password )
    local handshake = "< NTP/1.2 >< plugins_cve_id plugins_version timestamps dependencies fast_login >\n"

    local status, err = self.socket:send(handshake)
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send handshake to server" )
      err:setAbort(true)
      return false, err
    end

    local line
    status, line = self.socket:receive_buf(match.pattern_limit("\r?\n", 2048), false)
    if ( not(status) or line ~= "< NTP/1.2 >" ) then
      local err = brute.Error:new( "The server failed to respond to handshake" )
      err:setAbort( true )
      return false, err
    end

    status, line = self.socket:receive()
    if ( not(status) or line ~= "User : ") then
      local err = brute.Error:new( "Expected \"User : \", got something else" )
      err:setRetry( true )
      return false, err
    end

    status = self.socket:send(username .. "\n")
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send username to server" )
      err:setAbort( true )
      return false, err
    end

    status, line = self.socket:receive()
    if ( not(status) or line ~= "Password : ") then
      local err = brute.Error:new( "Expected \"Password : \", got something else" )
      err:setRetry( true )
      return false, err
    end

    status = self.socket:send(password)
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send password to server" )
      err:setAbort( true )
      return false, err
    end

    -- the line feed has to be sent separate like this, otherwise we don't
    -- receive the server response and the server simply hangs up
    status = self.socket:send("\n")
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send password to server" )
      err:setAbort( true )
      return false, err
    end

    -- we force a brief incorrect statement just to get an error message to
    -- confirm that we've successfully authenticated to the server
    local bad_cli_pref = "CLIENT <|> PREFERENCES <|>\n<|> CLIENT\n"
    status = self.socket:send(bad_cli_pref)
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send bad client preferences packet to server" )
      err:setAbort( true )
      return false, err
    end

    -- if the server disconnects us at this point, it's most likely due to
    -- that the authentication failed, so simply treat it as an incorrect
    -- password, rather than abort.
    status, line = self.socket:receive()
    if ( not(status) ) then
      return false, brute.Error:new( "Incorrect password" )
    end

    if ( line:match("SERVER <|> PREFERENCES_ERRORS <|>") ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    self.socket:close()
  end,

}

action = function(host, port)

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME

  -- the nessus service doesn't appear to do very well with multiple threads
  engine:setMaxThreads(1)
  local status, result = engine:start()

  return result
end
