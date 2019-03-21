local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local string    = require "string"
local stringaux = require "stringaux"

description = [[
CICS User ID enumeration script for the CESL/CESN Login screen.
]]

---
-- @args idlist Path to list of transaction IDs.
--  Defaults to the list of CICS transactions from IBM.
-- @args cics-user-enum.commands Commands in a semi-colon separated list needed
--  to access CICS. Defaults to <code>CICS</code>.
-- @args cics-user-enum.transaction By default this script uses the <code>CESL</code> transaction.
--  on some systems the transactio ID <code>CESN</code> is needed. Use this argument to change the
--  logon transaction ID.
--
-- @usage
-- nmap --script=cics-user-enum -p 23 <targets>
--
-- nmap --script=cics-user-enum --script-args userdb=users.txt,
-- cics-user-enum.commands="exit;logon applid(cics42)" -p 23 <targets>
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  tn3270
-- | cics-user-enum:
-- |   Accounts:
-- |     PLAGUE: Valid - CICS User ID
-- |_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0
--
-- @changelog
-- 2016-08-29 - v0.1 - created by Soldier of Fortran
-- 2016-12-19 - v0.2 - Added RACF support
-- 2019-02-01 - v0.3 - Disabled TN3270E support
--
-- @author Philip Young
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}
portrule = shortport.port_or_service({23,992}, "tn3270")

Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    o.tn3270 = tn3270.Telnet:new()
    o.tn3270:disable_tn3270e()
    return o
  end,
  connect = function( self )
    local status, err = self.tn3270:initiate(self.host,self.port)
    self.tn3270:get_screen_debug(2)
    if not status then
      stdnse.debug("Could not initiate TN3270: %s", err )
      return false
    end
    return true
  end,
  disconnect = function( self )
    self.tn3270:disconnect()
    self.tn3270 = nil
    return true
  end,
  login = function (self, user, pass) -- pass is actually the UserID we want to try
    local commands = self.options['commands']
    local transaction = self.options['trn']
    local timeout = 300
    local max_blank = 1
    local loop = 1
    local err
    stdnse.debug(2,"Getting to CICS")
    local run = stringaux.strsplit(";%s*", commands)
    for i = 1, #run do
      stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
      self.tn3270:send_cursor(run[i])
      self.tn3270:get_all_data()
      self.tn3270:get_screen_debug(2)
    end
    -- Are we at the logon transaction?
    if not (self.tn3270:find('SIGN ON TO CICS') and self.tn3270:find("Signon to CICS")) then
      -- We might be at some weird screen, lets try and exit it then clear it out
      stdnse.debug(2,"Sending: F3")
      self.tn3270:send_pf(3) -- send F3
      self.tn3270:get_all_data()
      stdnse.debug(2,"Clearing the Screen")
      self.tn3270:send_clear()
      self.tn3270:get_all_data()
      self.tn3270:get_screen_debug(2)
      stdnse.debug(2,"Sending Transaction ID: %s", transaction)
      self.tn3270:send_cursor(transaction)
      self.tn3270:get_all_data()
      -- Have we encoutered a slow system?
      if self.tn3270:isClear() then
        self.tn3270:get_all_data(1000)
      end
      self.tn3270:get_screen_debug(2)
    end
    -- At this point we MUST be at CESL/CESN to try accounts.
    -- If we're not then we quit with an error
    if not (self.tn3270:find('Type your userid and password')) then
    local err = brute.Error:new( "Can't get to Transaction CESN")
      err:setRetry( true )
      return false, err
    end

    -- Ok we're good we're at CESL/CESN. Enter the USERID.
    stdnse.verbose("Trying User ID: %s", pass)
    self.tn3270:send_cursor(pass)
    self.tn3270:get_all_data()
    stdnse.debug(2,"Screen Received for User ID: %s", pass)
    self.tn3270:get_screen_debug(2)
    if self.tn3270:find('TSS7145E') or
       self.tn3270:find('ACF01004') or
       self.tn3270:find('DFHCE3530') then
       -- known invalid userid messages
       -- TopSecret: TSS7145E
       -- ACF2:      ACF01004
       -- RACF:      DFHCE3530
      stdnse.debug("Invalid CICS User ID: %s", string.upper(pass))
      return false,  brute.Error:new( "Incorrect CICS User ID" )
    elseif self.tn3270:find('TSS7102E') or
           self.tn3270:find('ACF01012') or
           self.tn3270:find('DFHCE3523') then
      -- TopSecret: TSS7102E Password Missing
      -- ACF2:      ACF01012 PASSWORD NOT MATCHED
      -- RACF:      DFHCE3523 Please type your password.
      stdnse.verbose("Valid CICS User ID: %s", string.upper(pass))
      return true, creds.Account:new("CICS User", string.upper(pass), creds.State.VALID)
    else
      stdnse.verbose("Valid(?) CICS User ID: %s", string.upper(pass))
      -- The user may be valid for another reason, lets store that reason.
      stdnse.verbose(2,"User: " .. user .. " MSG:" .. self.tn3270:get_screen():sub(2,80))
      return true, creds.Account:new("CICS User: ".. string.upper(pass),'Reason: ' .. self.tn3270:get_screen():sub(2,80), creds.State.VALID)
    end

    return false, brute.Error:new("Something went wrong, we didn't get a proper response")
  end
}

--- Tests the target to see if we can even get to CICS
--
-- @param host host NSE object
-- @param port port NSE object
-- @param commands optional script-args of commands to use to get to CICS
-- @return status true on success, false on failure

local function cics_test( host, port, commands, transaction )
  stdnse.verbose(2,"Checking for CICS Login Page")
  local tn = tn3270.Telnet:new()
  tn:disable_tn3270e()
  local status, err = tn:initiate(host,port)
  local cesl = false -- initially we're not at CICS
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return false
  end
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  stdnse.debug("Getting to CICS")
  local run = stringaux.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    tn:send_cursor(run[i])
    tn:get_all_data()
    tn:get_screen_debug(2)
  end
  tn:get_all_data()
  tn:get_screen_debug(2) -- for debug purposes
  -- We should now be at CICS. Check if we're already at the logon screen
  if tn:find('Type your userid and password') then
    stdnse.verbose(2,"At CICS Login Transaction")
    tn:disconnect()
    return true
  end
  -- Uh oh. We're not at the logon screen. Now we need to send:
  --   * F3 to exit the CICS program
  --   * CLEAR (a tn3270 command) to clear the screen.
  --     (you need to clear before sending a transaction ID)
  --   * a known default CICS transaction ID with predictable outcome
  --     (CESF with 'Sign-off is complete.' as the result)
  -- to confirm that we were in CICS. If so we return true
  -- otherwise we return false
  local count = 1
  while not tn:isClear() and count < 6 do
    -- some systems will just kick you off others are slow in responding
    -- this loop continues to try getting out of whatever transaction 5 times. If it can't
    -- then we probably weren't in CICS to begin with.
    stdnse.debug(2,"Sending: F3")
    tn:send_pf(3) -- send F3
    tn:get_all_data()
    stdnse.debug(2,"Clearing the Screen")
    tn:send_clear()
    tn:get_all_data()
    tn:get_screen_debug(2)
    count = count + 1
  end
  if count == 5 then
    return false, 'Could not get to CICS after 5 attempts. Is this even CICS?'
  end
  stdnse.debug(2,"Sending %s", transaction)
  tn:send_cursor(transaction)
  tn:get_all_data()
  if tn:isClear() then
    tn:get_all_data(1000)
  end
  tn:get_screen_debug(2)

  if tn:find('SIGN ON TO CICS') or tn:find("Signon to CICS") then
      stdnse.verbose(2,"At CICS Login Transaction (%s)", transaction)
      tn:disconnect()
      return true
  end
  tn:disconnect()
  return false, 'Could not get to '.. transaction ..' (CICS Logon Screen)'
end

-- Filter iterator for unpwdb
-- IDs are limited to 8 alpha numeric and @, #, $ and can't start with a number
-- pattern:
--  ^%D     = The first char must NOT be a digit
-- [%w@#%$] = All letters including the special chars @, #, and $.
local valid_name = function(x)
  return (string.len(x) <= 8 and string.match(x,"^%D+[%w@#%$]"))
end

action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') or "cics"
  local transaction = stdnse.get_script_args(SCRIPT_NAME .. '.transaction') or "CESL"
  local cicstst, err = cics_test(host, port, commands, transaction)
  if cicstst then
    local options = { commands = commands, trn = transaction }
    stdnse.debug("Starting CICS User ID Enumeration")
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    engine:setPasswordIterator(unpwdb.filter_iterator(brute.usernames_iterator(),valid_name))
    engine.options.passonly = true
    engine.options:setTitle("CICS User ID")
    local status, result = engine:start()
    return result
  else
    return err
  end
end
