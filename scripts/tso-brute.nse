local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local nmap = require "nmap"
local string = require "string"

description = [[
TSO account brute forcer.

This script relies on the NSE TN3270 library which emulates a
TN3270 screen for NMAP.

TSO user IDs have the following rules:
 - it cannot begin with a number
 - only contains alpha-numeric characters and @, #, $.
 - it cannot be longer than 7 chars
]]

---
-- @usage
-- nmap -p 2401 --script tso-brute <host>
--
-- @output
-- 23/tcp open  tn3270  syn-ack IBM Telnet TN3270
-- | tso-brute:
-- |   Node Name:
-- |     IBMUSER:<skipped> - User logged on. Skipped.
-- |     ZERO:<skipped> - User logged on. Skipped.
-- |     COOL:secret - Valid credentials
-- |_  Statistics: Performed 6 guesses in 6 seconds, average tps: 1
-- Final times for host: srtt: 96305 rttvar: 72303  to: 385517
--
-- @args tso-brute.commands Commands in a semi-colon seperated list needed
--       to access TSO. Defaults to <code>TSO</code>.
--
-- @args tso-brute.always_logon TSO logon can kick a user off if it guesses
--       the correct password. always_logon, when set to <code>true</code>, will logon, even if
--       the user is logged in (kicking that user off). The default, <code>false</code> will
--       skip that account.
--
-- @changelog
-- 2015-10-29 - v0.1 - created by Soldier of Fortran
--
-- @author Philip Young
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--

author = "Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive"}

portrule = shortport.port_or_service({23,992,623}, {"tn3270"})

--- Registers User IDs that no longer need to be tested
--
-- @param username to stop checking
local function register_invalid( username )
  if nmap.registry.tsoinvalid == nil then
    nmap.registry.tsoinvalid = {}
  end
  stdnse.debug(2,"Registering %s", username)
  nmap.registry.tsoinvalid[username] = true
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
    return true
  end,
  disconnect = function( self )
    self.tn3270:disconnect()
    self.tn3270 = nil
    return true
  end,
  login = function (self, user, pass)

    local commands = self.options['key1']
    local always_logon = self.options['key2']
    local skip = self.options['skip']
    stdnse.debug(2,"Getting to TSO")
    local run = stdnse.strsplit(";%s*", commands)
    stdnse.verbose(2,"Trying User ID/Password: %s/%s", user, pass)
    for i = 1, #run do
      stdnse.debug(2,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
      if i == #run and run[i]:upper():find("LOGON APPLID") and skip then
        stdnse.debug(2,"Trying User ID: %s", user)
        self.tn3270:send_cursor(run[i] .. " DATA(" .. user .. ")")
      elseif i == #run and skip then
        stdnse.debug(2,"Trying User ID: %s", user)
        self.tn3270:send_cursor(run[i] .. " " .. user)
      else
        self.tn3270:send_cursor(run[i])
      end
      self.tn3270:get_all_data()
    end

    if self.tn3270:find("%*%*%*") then -- For ACF2/TopSecret if required
      self.tn3270:send_enter()
      self.tn3270:get_all_data()
    end

    if not self.tn3270:find("ENTER USERID")
       and not self.tn3270:find("TSO/E LOGON")
       and not self.tn3270:find("IKJ56710I INVALID USERID") then
      local err = brute.Error:new( "TSO Unavailable" )
        -- This error occurs on too many concurrent application requests it
        -- should be temporary. We use the new setReduce function.
      err:setReduce(true)
      stdnse.debug(1,"TSO Unavailable for UserID %s", pass )
      return false, err
    end

    if not skip then
      stdnse.debug(2,"Trying User ID: %s", user)
      self.tn3270:send_cursor(user)
      self.tn3270:get_all_data()
    end


    stdnse.debug(2,"Screen Received for User ID: %s", user)
    self.tn3270:get_screen_debug(2)

    if not self.tn3270:find('Enter LOGON parameters below') then
      stdnse.debug(2,"Screen Received for User ID: %s", user)
      self.tn3270:get_screen_debug(2)
        -- This error occurs on too many concurrent application requests it
        -- should be temporary. We use the new setReduce function.
      local err = brute.Error:new( "Not at TSO" )
      err:setReduce(true)
      stdnse.debug(1,"TSO Unavailable for UserID %s", pass )
      return false, err
    end

    if self.tn3270:find('not authorized to use TSO') then -- invalid user ID
      stdnse.debug(2,"Got Message: IKJ56420I Userid %s not authorized to use TSO.", user)
      -- Store the invalid ID in the registry so we don't keep trying it with subsequent passwords
      -- when using the brute library.
      register_invalid(user)
      return false,  brute.Error:new( "User ID not authorized to use TSO" )
    else
      -- It's a valid account so lets try a password
      stdnse.debug(2,"%s is a valid TSO User ID. Trying Password: %s", string.upper(user), pass)
      if always_logon then
        local writeable = self.tn3270:writeable()
        -- This turns on the 'reconnect' which may boot users off
        self.tn3270:send_locations({{writeable[1][1],pass},{writeable[11][1],"S"}})
      else
        self.tn3270:send_cursor(pass)
      end

      self.tn3270:get_all_data()
      while self.tn3270:isClear() do
        -- the screen is blank for a few while it loads TSO
        self.tn3270:get_all_data()
      end

      stdnse.debug(2,"Screen Received for User/Pass: %s/%s", user, pass)
      self.tn3270:get_screen_debug(2)

      if not always_logon and self.tn3270:find("already logged on") then
        -- IKJ56425I LOGON rejected User already logged on to system
        register_invalid(user)
        return true, creds.Account:new(user, "<skipped>", "User logged on. Skipped.")
      elseif not (self.tn3270:find("IKJ56421I") or
          self.tn3270:find("TSS7101E")  or
          self.tn3270:find("TSS714[0-3]E")  or
          self.tn3270:find("TSS7120E")) then
        -- RACF:
        -- IKJ56421I PASSWORD NOT AUTHORIZED FOR USERID

        -- Top Secret:
        -- TSS7101E Password is Incorrect
        -- TSS7140E Accessor ID Has Expired: No Longer Valid
        -- TSS7141E Use of Accessor ID Suspended
        -- TSS7142E Accessor ID Not Yet Available for Use - Still Inactive
        -- TSS7143E Accessor ID Has Been Inactive Too Long
        -- TSS7120E PASSWORD VIOLATION THRESHOLD EXCEEDED

        -- The 'MSG allows testers to discern any relevant messages they may get for the account'
        stdnse.verbose(2,"Valid User/Pass: " .. user .. "/" .. pass)
        stdnse.verbose(3,"Valid MSG for " .. user .. "/" .. pass .. ": " .. self.tn3270:get_screen():sub(1,80))
        return true, creds.Account:new(user, pass, creds.State.VALID)
      else
        return false, brute.Error:new( "Incorrect password" )
      end
    end
  end
}

--- Tests the target to see if we can even get to TSO
--
-- @param host host NSE object
-- @param port port NSE object
-- @param commands script-args of commands to use to get to TSO
-- @return status true on success, false on failure
-- @return name of security product installed
local function tso_test( host, port, commands )
  stdnse.debug("Checking for TSO")
  local tn = tn3270.Telnet:new()
  local status, err = tn:initiate(host,port)
  local tso = false -- initially we're not at TSO logon panel
  local secprod = "RACF"
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return tso, "Could not Initiate TN3270"
  end
  local run = stdnse.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(2,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    tn:send_cursor(run[i])
    tn:get_all_data()
  end
  tn:get_screen_debug(2)

  if tn:find("***") then
    secprod = "TopSecret/ACF2"
  end

  if tn:find("ENTER USERID") or tn:find("TSO/E LOGON")  then
    tso = true
    -- Patch OA44855 removed the ability to enumerate users
    tn:send_cursor("notreal")
    tn:get_all_data()
    if tn:find("IKJ56476I ENTER PASSWORD") then
      return false, secprod, "Enumeration is not possible. PASSWORDPREPROMPT is set to ON."
    end
  end
  tn:send_pf(3)
  tn:disconnect()
  return tso, secprod, "Could not get to TSO. Try --script-args=tso-enum.commands='logon applid(tso)'. Aborting."
end

--- Tests the target to see if we can speed up brute forcing
-- VTAM/USSTable will sometimes allow you to put the userid
-- in the command area either through data() or just adding
-- the userid. This function will test for both
--
-- @param host host NSE object
-- @param port port NSE object
-- @param commands script-args of commands to use to get to TSO
-- @return status true on success, false on failure
local function tso_skip( host, port, commands )
  stdnse.debug("Checking for IKJ56700A message skip")
  local tn = tn3270.Telnet:new()
  stdnse.debug2("Connecting TN3270 to %s:%s", host.targetname or host.ip, port.number)
  local status, err = tn:initiate(host,port)
  stdnse.debug2("Displaying initial TN3270 Screen:")
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return false
  end
  -- We're connected now to test.
  local data = false
  if commands:upper():find('LOGON APPLID') then
    stdnse.debug(2,"Using LOGON command (%s) trying DATA() command", commands )
    data = true
  else
    stdnse.debug(2,"Not using LOGON command, testing adding userid to command" )
  end

  local run = stdnse.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(2,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    if i == #run then
      if data then
        stdnse.debug(2,"Sending "..run[i].." DATA(FAKEUSER)")
        tn:send_cursor(run[i].." DATA(FAKEUSER)")
      else
        stdnse.debug(2,"Sending "..run[i].." FAKEUSER")
        tn:send_cursor(run[i].." FAKEUSER")
      end
    else
      tn:send_cursor(run[i])
    end
    tn:get_all_data()
  end
  tn:get_screen_debug(2)

  if tn:find("IKJ56710I INVALID USERID")     or
     tn:find("Enter LOGON parameters below") then
    stdnse.debug('IKJ56700A message skip supported')
    return true
  else
    return false
  end
end

-- Filter iterator for unpwdb usernames
-- TSO is limited to 7 alpha numeric and @, #, $ and can't start with a number
-- If this user ID has been confirmed to not be a valid TSO account
-- it will stop being passed to the brute engine
-- pattern:
--  ^%D     = The first char must NOT be a digit
-- [%w@#%$] = All letters including the special chars @, #, and $.
local valid_name = function(x)
  if  nmap.registry.tsoinvalid and nmap.registry.tsoinvalid[x] then
    return false
  else
    return (string.len(x) <= 7 and string.match(x,"^%D+[%w@#%$]"))
  end
end

-- Checks string to see if it follows valid password limitations
local valid_pass = function(x)
  local patt = "[%w@#%$]"
  return (string.len(x) <= 8 and string.match(x,patt))
end

action = function( host, port )
  local status, result
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') or "tso"
  -- if a user is logged on this script will not try to logon as that user
  -- because a user is only allowed to logon from one location. If you turn always_logon on
  -- it will logon if it finds a valid username/password, kicking that user off
  local always_logon = stdnse.get_script_args(SCRIPT_NAME .. '.always_logon') or false
  local tsotst, secprod, err = tso_test(host, port, commands)
  if tsotst then
    stdnse.debug("Starting TSO Brute Force")
    local options = { key1 = commands, key2 = always_logon, skip = tso_skip(host, port, commands) }
    local engine = brute.Engine:new(Driver, host, port, options)
    -- TSO has username/password restrictions.
    -- This sets the iterators to use only valid TSO userids/passwords
    engine:setUsernameIterator(unpwdb.filter_iterator(brute.usernames_iterator(),valid_name))
    engine:setPasswordIterator(unpwdb.filter_iterator(brute.passwords_iterator(),valid_pass))
    engine.options.script_name = SCRIPT_NAME
    engine.options:setTitle("TSO Accounts")
    status, result = engine:start()
    return result
  else
   return err
  end
end
