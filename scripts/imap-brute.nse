local brute = require "brute"
local coroutine = require "coroutine"
local creds = require "creds"
local imap = require "imap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
]]

---
-- @usage
-- nmap -p 143,993 --script imap-brute <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 143/tcp open  imap    syn-ack
-- | imap-brute:
-- |   Accounts
-- |     braddock:jules - Valid credentials
-- |     lane:sniper - Valid credentials
-- |     parker:scorpio - Valid credentials
-- |   Statistics
-- |_    Performed 62 guesses in 10 seconds, average tps: 6
--
-- @args imap-brute.auth authentication mechanism to use LOGIN, PLAIN,
--                       CRAM-MD5, DIGEST-MD5 or NTLM

-- Version 0.1
-- Created 07/15/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service({143,993}, {"imap","imaps"})

local mech

-- By using this connectionpool we don't need to reconnect the socket
-- for each attempt.
ConnectionPool = {}

Driver =
{

  -- Creates a new driver instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param pool an instance of the ConnectionPool
  new = function(self, host, port, pool)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the server (retrieves a connection from the pool)
  connect = function( self )
    self.helper = ConnectionPool[coroutine.running()]
    if ( not(self.helper) ) then
      self.helper = imap.Helper:new( self.host, self.port )
      self.helper:connect()
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

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)

  -- Connects to the server and retrieves the capabilities so that
  -- authentication mechanisms can be determined
  local helper = imap.Helper:new(host, port)
  local status = helper:connect()
  if (not(status)) then return fail("Failed to connect to the server.") end
  local status, capabilities = helper:capabilities()
  if (not(status)) then return fail("Failed to retrieve capabilities.") end

  -- check if an authentication mechanism was provided or try
  -- try them in the mech_prio order
  local mech_prio = stdnse.get_script_args("imap-brute.auth")
  mech_prio = ( mech_prio and { mech_prio } ) or
    { "LOGIN", "PLAIN", "CRAM-MD5", "DIGEST-MD5", "NTLM" }

  -- iterates over auth mechanisms until a valid mechanism is found
  for _, m in ipairs(mech_prio) do
    if ( m == "LOGIN" and not(capabilities.LOGINDISABLED)) then
      mech = "LOGIN"
      break
    elseif ( capabilities["AUTH=" .. m] ) then
      mech = m
      break
    end
  end

  -- if no mechanisms were found, abort
  if ( not(mech) ) then
    return fail("No suitable authentication mechanism was found")
  end

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()

  for _, helper in pairs(ConnectionPool) do helper:close() end

  return result
end
