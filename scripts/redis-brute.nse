local brute = require "brute"
local creds = require "creds"
local redis = require "redis"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force passwords auditing against a Redis key-value store.
]]

---
-- @usage
-- nmap -p 6379 <ip> --script redis-brute
--
-- @output
-- PORT     STATE SERVICE
-- 6379/tcp open  unknown
-- | redis-brute:
-- |   Accounts
-- |     toledo - Valid credentials
-- |   Statistics
-- |_    Performed 5000 guesses in 3 seconds, average tps: 1666
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(6379, "redis")

local function fail(err) return stdnse.format_output(false, err) end

Driver = {

  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    self.helper = redis.Helper:new(self.host, self.port)
    return self.helper:connect(brute.new_socket())
  end,

  login = function( self, username, password )
    local status, response = self.helper:reqCmd("AUTH", password)

    -- some error occurred, attempt to retry
    if ( status and response.type == redis.Response.Type.ERROR and
      "-ERR invalid password" == response.data ) then
      return false, brute.Error:new( "Incorrect password" )
    elseif ( status and response.type == redis.Response.Type.STATUS and
      "+OK" ) then
      return true, creds.Account:new( "", password, creds.State.VALID)
    else
      local err = brute.Error:new( response.data )
      err:setRetry( true )
      return false, err
    end

  end,

  disconnect = function(self)
    return self.helper:close()
  end,

}


local function checkRedis(host, port)

  local helper = redis.Helper:new(host, port)
  local status = helper:connect()
  if( not(status) ) then
    return false, "Failed to connect to server"
  end

  local status, response = helper:reqCmd("INFO")
  if ( not(status) ) then
    return false, "Failed to request INFO command"
  end

  if ( redis.Response.Type.ERROR == response.type ) then
    if ( "-ERR operation not permitted" == response.data ) or
        ( "-NOAUTH Authentication required." == response.data) then
      return true
    end
  end

  return false, "Server does not require authentication"
end

action = function(host, port)

  local status, err =  checkRedis(host, port)
  if ( not(status) ) then
    return fail(err)
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.options:setOption( "passonly", true )

  local result
  status, result = engine:start()
  return result
end
