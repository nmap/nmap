local brute = require "brute"
local creds = require "creds"
local shortport = require "shortport"
local socks = require "socks"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against SOCKS 5 proxy servers.
]]

---
-- @usage
-- nmap --script socks-brute -p 1080 <host>
--
-- @output
-- PORT     STATE SERVICE
-- 1080/tcp open  socks
-- | socks-brute:
-- |   Accounts
-- |     patrik:12345 - Valid credentials
-- |   Statistics
-- |_    Performed 1921 guesses in 6 seconds, average tps: 320
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


portrule = shortport.port_or_service({1080, 9050}, {"socks", "socks5", "tor-socks"})

Driver = {

  new = function (self, host, port)
    local o = { host = host, port = port }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  connect = function ( self )
    self.helper = socks.Helper:new(self.host, self.port, { timeout = 10000 })
    return self.helper:connect()
  end,

  login = function( self, username, password )
    local status, err = self.helper:authenticate({username=username, password=password})

    if (not(status)) then
      -- the login failed
      if ( "Authentication failed" == err ) then
        return false, brute.Error:new( "Login failed" )
      end

      -- something else happened, let's retry
      local err = brute.Error:new( err )
      err:setRetry( true )
      return false, err
    end

    return true, creds.Account:new(username, password, creds.State.VALID)
  end,

  disconnect = function( self )
    return self.helper:close()
  end,
}

local function checkAuth(host, port)

  local helper = socks.Helper:new(host, port)
  local status, response = helper:connect()
  if ( not(status) ) then
    return false, response
  end

  if ( response.method == socks.AuthMethod.NONE ) then
    return false, "\n  No authentication required"
  end

  local status, err = helper:authenticate({username="nmap", password="nmapbruteprobe"})
  if ( err ~= "Authentication failed" ) then
    return false, err
  end

  helper:close()
  return true
end

action = function(host, port)

  local status, response = checkAuth(host, port)
  if ( not(status) ) then
    return stdnse.format_output(false, response)
  end

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()
  return result
end
