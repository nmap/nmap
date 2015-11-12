local brute = require "brute"
local coroutine = require "coroutine"
local creds = require "creds"
local shortport = require "shortport"
local stdnse = require "stdnse"
local xmpp = require "xmpp"

description = [[
Performs brute force password auditing against XMPP (Jabber) instant messaging servers.
]]

---
-- @usage
-- nmap -p 5222 --script xmpp-brute <host>
--
-- @output
-- PORT     STATE SERVICE
-- 5222/tcp open  xmpp-client
-- | xmpp-brute:
-- |   Accounts
-- |     CampbellJ:arthur321 - Valid credentials
-- |     CampbellA:joan123 - Valid credentials
-- |     WalkerA:auggie123 - Valid credentials
-- |   Statistics
-- |_    Performed 6237 guesses in 5 seconds, average tps: 1247
--
-- @args xmpp-brute.auth authentication mechanism to use LOGIN, PLAIN, CRAM-MD5
--                       or DIGEST-MD5
-- @args xmpp-brute.servername needed when host name cannot be automatically
--                             determined (eg. when running against an IP,
--                             instead of hostname)
--

-- Version 0.1
-- Created 07/21/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service(5222, {"jabber", "xmpp-client"})

local mech

ConnectionPool = {}

Driver =
{

  -- Creates a new driver instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param pool an instance of the ConnectionPool
  new = function(self, host, port, options )
    local o = { host = host, port = port, options = options }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the server (retrieves a connection from the pool)
  connect = function( self )
    self.helper = ConnectionPool[coroutine.running()]
    if ( not(self.helper) ) then
      self.helper = xmpp.Helper:new( self.host, self.port, self.options )
      local status, err = self.helper:connect()
      if ( not(status) ) then return false, err end
      ConnectionPool[coroutine.running()] = self.helper
    end
    return true
  end,

  -- Attempts to login to the server
  -- @param username string containing the username
  -- @param password string containing the password
  -- @return status true on success, false on failure
  -- @return brute.Error on failure and creds.Account on success
  login = function( self, username, password )
    local status, err = self.helper:login( username, password, mech )
    if ( status ) then
      self.helper:close()
      self.helper:connect()
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    if ( err:match("^ERROR: Failed to .* data$") ) then
      self.helper:close()
      self.helper:connect()
      local err = brute.Error:new( err )
      -- This might be temporary, set the retry flag
      err:setRetry( true )
      return false, err
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  -- Disconnects from the server (release the connection object back to
  -- the pool)
  disconnect = function( self )
    return true
  end,

}

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local options = { servername = stdnse.get_script_args("xmpp-brute.servername") }
  local helper = xmpp.Helper:new(host, port, options)
  local status, err = helper:connect()
  if ( not(status) ) then
    return fail("Failed to connect to XMPP server")
  end

  local mechs = helper:getAuthMechs()
  if ( not(mechs) ) then
    return fail("Failed to retrieve authentication mechs from XMPP server")
  end

  local mech_prio = stdnse.get_script_args("xmpp-brute.auth")
  mech_prio = ( mech_prio and { mech_prio } ) or { "PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5"}

  for _, mp in ipairs(mech_prio) do
    for m, _ in pairs(mechs) do
      if ( mp == m ) then mech = m; break end
    end
    if ( mech ) then break end
  end

  if ( not(mech) ) then
    return fail("Failed to find suitable authentication mechanism")
  end

  local engine = brute.Engine:new(Driver, host, port, options)
  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()

  return result

end
