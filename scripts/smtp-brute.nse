local brute = require "brute"
local coroutine = require "coroutine"
local creds = require "creds"
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
]]

---
-- @usage
-- nmap -p 25 --script smtp-brute <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 25/tcp  open  stmp    syn-ack
-- | smtp-brute:
-- |   Accounts
-- |     braddock:jules - Valid credentials
-- |     lane:sniper - Valid credentials
-- |     parker:scorpio - Valid credentials
-- |   Statistics
-- |_    Performed 1160 guesses in 41 seconds, average tps: 33
--
-- @args smtp-brute.auth authentication mechanism to use LOGIN, PLAIN,
--                       CRAM-MD5, DIGEST-MD5 or NTLM

-- Version 0.1
-- Created 07/15/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

portrule = shortport.port_or_service({ 25, 465, 587 },
                { "smtp", "smtps", "submission" })

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
  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the server (retrieves a connection from the pool)
  connect = function( self )
    self.socket = ConnectionPool[coroutine.running()]
    if ( not(self.socket) ) then
      self.socket = smtp.connect(self.host, self.port, { ssl = true, recv_before = true })
      if ( not(self.socket) ) then return false end
      ConnectionPool[coroutine.running()] = self.socket
    end
    return true
  end,

  -- Attempts to login to the server
  -- @param username string containing the username
  -- @param password string containing the password
  -- @return status true on success, false on failure
  -- @return brute.Error on failure and creds.Account on success
  login = function( self, username, password )
    local status, err = smtp.login( self.socket, username, password, mech )
    if ( status ) then
      smtp.quit(self.socket)
      ConnectionPool[coroutine.running()] = nil
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    if ( err:match("^ERROR: Failed to .*") ) then
      self.socket:close()
      ConnectionPool[coroutine.running()] = nil
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

  local socket, response = smtp.connect(host, port, { ssl = true, recv_before = true })
  if ( not(socket) ) then return fail("Failed to connect to SMTP server") end
  local status, response = smtp.ehlo(socket, smtp.get_domain(host))
  if ( not(status) ) then return fail("EHLO command failed, aborting ...") end
  local mechs = smtp.get_auth_mech(response)
  if ( not(mechs) ) then
    return fail("Failed to retrieve authentication mechanisms form server")
  end
  smtp.quit(socket)

  local mech_prio = stdnse.get_script_args("smtp-brute.auth")
  mech_prio = ( mech_prio and { mech_prio } ) or
    { "LOGIN", "PLAIN", "CRAM-MD5", "DIGEST-MD5", "NTLM" }

  for _, mp in ipairs(mech_prio) do
    for _, m in pairs(mechs) do
      if ( mp == m ) then
        mech = m
        break
      end
    end
    if ( mech ) then break end
  end

  local engine = brute.Engine:new(Driver, host, port)

  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()

  for _, sock in pairs(ConnectionPool) do sock:close() end

  return result
end
