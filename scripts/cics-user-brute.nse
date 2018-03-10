local nmap = require "nmap"
local string = require "string"
local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"

description = [[
CICS User ID brute forcing script for the CESL login screen.
]]

---
-- @args cics-user-brute.commands Commands in a semi-colon seperated list needed
--  to access CICS. Defaults to <code>CICS</code>.
--
-- @usage
-- nmap --script=cics-user-brute -p 23 <targets>
--
-- nmap --script=cics-user-brute --script-args userdb=users.txt,
-- cics-user-brute.commands="exit;logon applid(cics42)" -p 23 <targets>
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  tn3270
-- | cics-user-brute:
-- |   Accounts:
-- |     PLAGUE: Valid - CICS User ID
-- |_  Statistics: Performed 31 guesses in 114 seconds, average tps: 0

-- @changelog
-- 2016-08-29 - v0.1 - created by Soldier of Fortran
-- 2016-10-26 - v0.2 - Added RACF support
-- 2017-01-23 - v0.3 - Rewrote script to use fields and skip enumeration to speed up testing

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}
portrule = shortport.port_or_service({23,992}, "tn3270")

--- Registers User IDs that no longer need to be tested
--
-- @param username to stop checking
local function register_invalid( username )
  if nmap.registry.cicsinvalid == nil then
    nmap.registry.cicsinvalid = {}
  end
  stdnse.debug(2,"Registering %s", username)
  nmap.registry.cicsinvalid[username] = true
end

Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    o.tn3270 = tn3270.Telnet:new(brute.new_socket())
    return o
  end,
  connect = function( self )
    local status, err = self.tn3270:initiate(self.host,self.port)
    self.tn3270:get_screen_debug(2)
    if not status then
      stdnse.debug("Could not initiate TN3270: %s", err )
      return false
    end
    stdnse.debug(2,"Connect Successful")
    return true
  end,
  disconnect = function( self )
    self.tn3270:disconnect()
    self.tn3270 = nil
    return true
  end,
  login = function (self, user, pass)
    local commands = self.options['key1']
    local timeout = 300
    local max_blank = 1
    local loop = 1
    local err
    stdnse.debug(2,"Getting to CICS")
    local run = stdnse.strsplit(";%s*", commands)
    for i = 1, #run do
      stdnse.debug(2,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
      self.tn3270:send_cursor(run[i])
      self.tn3270:get_all_data()
      self.tn3270:get_screen_debug(2)
    end
    -- Are we at the logon transaction?
    if not (self.tn3270:find('SIGN ON TO CICS') or self.tn3270:find("Signon to CICS")) then
      -- We might be at some weird screen, lets try and exit it then clear it out
      stdnse.debug(2,"Sending: F3")
      self.tn3270:send_pf(3) -- send F3
      self.tn3270:get_all_data()
      stdnse.debug(2,"Clearing the Screen")
      self.tn3270:send_clear()
      self.tn3270:get_all_data()
      self.tn3270:get_screen_debug(2)
      stdnse.debug(2,"Sending 'CESL'")
      self.tn3270:send_cursor('CESL')
      self.tn3270:get_all_data()
      -- Have we encoutered a slow system?
      if self.tn3270:isClear() then
          self.tn3270:get_all_data(1000)
        end
        self.tn3270:get_screen_debug(2)
    end
      -- At this point we MUST be at CESL to try accounts.
      -- If we're not then we quit with an error
    if not (self.tn3270:find('SIGN ON TO CICS') or self.tn3270:find("Signon to CICS")) then
      local err = brute.Error:new( "Can't get to CESL")
      err:setRetry( true )
      return false, err
    end

      -- Ok we're good we're at CESL. Send the Userid and Password.
    local fields = self.tn3270:writeable() -- Get the writeable field areas
    local user_loc = {fields[1][1],user}   -- This is the 'UserID:' field
    local pass_loc = {fields[3][1],pass}   -- This is the 'Password:' field ([2] is a group ID)
    stdnse.verbose('Trying CICS: ' .. user ..' : ' .. pass)
    self.tn3270:send_locations({user_loc,pass_loc})
    self.tn3270:get_all_data()
    stdnse.debug(2,"Screen Received for User ID: %s/%s", user, pass)
    self.tn3270:get_screen_debug(2)

    local loop = 1
    while loop < 300 and self.tn3270:find('DFHCE3520') do -- still at Enter UserID message?
      stdnse.verbose('Trying CICS: ' .. user ..' : ' .. pass)
      self.tn3270:send_locations({user_loc,pass_loc})
      self.tn3270:get_all_data()
      stdnse.debug(2,"Screen Received for User ID: %s/%s", user, pass)
      self.tn3270:get_screen_debug(2)
      loop = loop + 1 -- We don't want this to loop forever
    end

    if loop == 300 then
      local err = brute.Error:new( "Error with UserID entry")
      err:setRetry( true )
      return false, err
    end

    -- Now check what we received if its valid or not
    if self.tn3270:find('TSS7101E') or
       self.tn3270:find('DFHCE3530') or
       self.tn3270:find('DFHCE3532') then
      -- Top Secret:
      -- TSS7101E Password is Incorrect
      -- RACF:
      -- DFHCE3530/2 Your userid or password is invalid. Please retype both.
      return false, brute.Error:new( "Incorrect password" )
    elseif self.tn3270:find('TSS7145E') or
           self.tn3270:find("TSS714[0-3]E")  or
           self.tn3270:find('TSS7160E') or
           self.tn3270:find('TSS7120E') then
      -- Top Secret:
      -- TSS7140E Accessor ID Has Expired: No Longer Valid
      -- TSS7141E Use of Accessor ID Suspended
      -- TSS7142E Accessor ID Not Yet Available for Use - Still Inactive
      -- TSS7143E Accessor ID Has Been Inactive Too Long
      -- TSS7120E PASSWORD VIOLATION THRESHOLD EXCEEDED
      -- TSS7145E ACCESSOR ID <acid> NOT DEFINED TO SECURITY
      -- TSS7160E Facility <X> Not Authorized for Your Use
      -- Store the invalid ID in the registry so we don't keep trying it with subsequent passwords
      -- when using default brute library.
      register_invalid(user)
      return false,  brute.Error:new( "User ID Not Able to Use CICS" )
    elseif self.tn3270:find("DFHCE3549") or
           self.tn3270:find('TSS7000I')  or
           self.tn3270:find('TSS7110E Password Has Expired. New Password Missing')  or
           self.tn3270:find('TSS7001I')  then
      stdnse.verbose("Valid CICS UserID / Password: " .. user .. "/" .. pass)
      return true, creds.Account:new(user, pass, creds.State.VALID)
    else
      -- ok whoa, something happened, print the screen but don't store as valid
      stdnse.verbose("Valid(?) user/pass with current output " .. user .. "/" .. pass .. "\n" ..  self.tn3270:get_screen())
      return false, brute.Error:new( "Incorrect password" )
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

local function cics_test( host, port, commands )
  stdnse.verbose(2,"Checking for CICS Login Page")
  local tn = tn3270.Telnet:new()
  local status, err = tn:initiate(host,port)
  local cesl = false -- initially we're not at CICS
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return false
  end
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  stdnse.debug(2,"Getting to CICS")
  local run = stdnse.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(2,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    tn:send_cursor(run[i])
    tn:get_all_data()
    tn:get_screen_debug(2)
  end
  tn:get_all_data()
  tn:get_screen_debug(2) -- for debug purposes
  -- We should now be at CICS. Check if we're already at the logon screen
  if tn:find('SIGN ON TO CICS') and tn:find("Signon to CICS") then
    stdnse.verbose(2,"At CICS Login Transaction (CESL)")
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
  stdnse.debug(2,"Sending 'CESL'")
  tn:send_cursor('CESL')
  tn:get_all_data()
  if tn:isClear() then
    tn:get_all_data(1000)
  end
  tn:get_screen_debug(2)

  if tn:find("Signon to CICS") then
      stdnse.verbose(2,"At CICS Login Transaction (CESL)")
      tn:disconnect()
      return true
  end
  tn:disconnect()
  return false, 'Could not get to CESL (CICS Logon Screen)'
end

-- Filter iterator for unpwdb
-- IDs are limited to 8 alpha numeric and @, #, $ and can't start with a number
-- pattern:
--  ^%D     = The first char must NOT be a digit
-- [%w@#%$] = All letters including the special chars @, #, and $.
local valid_name = function(x)
  if  nmap.registry.tsoinvalid and nmap.registry.tsoinvalid[x] then
    return false
  end
  return (string.len(x) <= 8 and string.match(x,"^%D+[%w@#%$]"))
end

-- Checks string to see if it follows valid password limitations
local valid_pass = function(x)
  return (string.len(x) <= 8 )
end

action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') or "cics"
  local cicstst, err = cics_test(host, port, commands)
  if cicstst then
    local options = { key1 = commands }
    local engine = brute.Engine:new(Driver, host, port, options)
    stdnse.debug(2,"Starting CICS Brute Forcing")
    engine:setUsernameIterator(unpwdb.filter_iterator(brute.usernames_iterator(),valid_name))
    engine:setPasswordIterator(unpwdb.filter_iterator(brute.passwords_iterator(),valid_pass))
    engine.options.script_name = SCRIPT_NAME
    engine.options:setTitle("CICS User Accounts")
    local status, result = engine:start()
    return result
  else
    return err
  end
end
