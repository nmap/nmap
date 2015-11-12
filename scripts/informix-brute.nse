local brute = require "brute"
local creds = require "creds"
local informix = require "informix"
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"

description = [[
Performs brute force password auditing against IBM Informix Dynamic Server.
]]

---
-- @usage
-- nmap --script informix-brute -p 9088 <host>
--
-- @output
-- PORT     STATE SERVICE
-- 9088/tcp open  unknown
-- | informix-brute:
-- |   Accounts
-- |     ifxnoob:ifxnoob => Valid credentials
-- |   Statistics
-- |_    Perfomed 25024 guesses in 75 seconds, average tps: 320
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--

--
-- Version 0.1
-- Created 07/23/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service( { 1526, 9088, 9090, 9092 }, "informix", "tcp", "open")

Driver =
{

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  --- Connects performs protocol negotiation
  --
  -- @return true on success, false on failure
  connect = function( self )
    local status, data
    self.helper = informix.Helper:new( self.host, self.port, "on_nmap_dummy" )

    status, data = self.helper:Connect()
    if ( not(status) ) then
      return status, data
    end

    return true
  end,

  --- Attempts to login to the Informix server
  --
  -- @param username string containing the login username
  -- @param password string containing the login password
  -- @return status, true on success, false on failure
  -- @return brute.Error object on failure
  --         creds.Account object on success
  login = function( self, username, password )
    local status, data = self.helper:Login( username, password, {} )

    if ( status ) then
      if ( not(nmap.registry['informix-brute']) ) then
        nmap.registry['informix-brute'] = {}
      end
      table.insert( nmap.registry['informix-brute'], { ["username"] = username, ["password"] = password } )
      return true, creds.Account:new(username, password, creds.State.VALID)
      -- Check for account locked message
    elseif ( data:match("INFORMIXSERVER does not match either DBSERVERNAME or DBSERVERALIASES") ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    return false, brute.Error:new( data )

  end,

  --- Disconnects and terminates the Informix communication
  disconnect = function( self )
    self.helper:Close()
  end,

}


action = function(host, port)
  local status, result
  local engine = brute.Engine:new(Driver, host, port )
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()

  return result
end
