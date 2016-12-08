local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local nmap = require "nmap"
local string = require "string"

description = [[
TSO User ID enumerator for IBM mainframes (z/OS). The TSO logon panel
tells you when a user ID is valid or invalid with the message:
 <code>IKJ56420I Userid <user ID> not authorized to use TSO</code>.

The TSO logon process can work in two ways:
1) You get prompted with <code>IKJ56700A ENTER USERID -</code>
   to which you reply with the user you want to use.
   If the user ID is valid it will give you a normal
   TSO logon screen. Otherwise it will give you the
   screen logon error above.
2) You're given the TSO logon panel and enter your user ID
   at the <code>Userid    ===></code> prompt. If you give
   it an invalid user ID you receive the error message above.

This script relies on the NSE TN3270 library which emulates a
TN3270 screen for NMAP.

TSO user IDs have the following rules:
 - it cannot begin with a number
 - only contains alpha-numeric characters and @, #, $.
 - it cannot be longer than 7 chars
]]

---
-- @args tso-enum.commands Commands in a semi-colon seperated list needed
-- to access TSO. Defaults to <code>tso</code>.
--
-- @usage
-- nmap --script=tso-enum -p 23 <targets>
--
-- @usage
-- nmap -sV -p 9923 10.32.70.10 --script tso-enum --script-args userdb=tso_users.txt,tso-enum.commands="logon applid(tso)"
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 23/tcp open  tn3270  IBM Telnet TN3270
-- | tso-enum:
-- |   TSO User ID:
-- |     TSO User:RAZOR -  Valid User ID
-- |     TSO User:BLADE -  Valid User ID
-- |     TSO User:PLAGUE -  Valid User ID
-- |_  Statistics: Performed 6 guesses in 3 seconds, average tps: 2
--
-- @changelog
-- 2015-07-04 - v0.1 - created by Soldier of Fortran
-- 2015-10-30 - v0.2 - streamlined the code, relying on brute and unpwdb and
--                     renamed to tso-enum.


author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({23,992,623}, {"tn3270"})

Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    o.tn3270 = tn3270.Telnet:new()
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
    self.tn3270:send_pf(3)
    self.tn3270:disconnect()
    self.tn3270 = nil
    return true
  end,
  login = function (self, user, pass)
  -- pass is actually the user id we want to try
    local commands = self.options['key1']
    local cmd_DATA = false
    stdnse.debug(2,"Getting to TSO")
    local run = stdnse.strsplit(";%s*", commands)
    for i = 1, #run do
      stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
      if string.find(string.upper(run[i]),"logon applid") ~= nil then
        stdnse.verbose(2,"Trying User ID: %s", pass)
        self.tn3270:send_cursor(run[i] .. " DATA(" .. pass .. ")")
        cmd_DATA = true
      else
        self.tn3270:send_cursor(run[i])
      end
      self.tn3270:get_all_data()
    end

    self.tn3270:get_screen_debug(2)

    if not self.tn3270:find("ENTER USERID") and not self.tn3270:find("TSO/E LOGON")  then
      local err = brute.Error:new( "TSO Unavailable" )
        -- This error occurs on too many concurrent application requests it
        -- should be temporary. If not, the script errors and less threads should be used.
      err:setRetry( true )
      return false, err
    end

    if not cmd_DATA then
      stdnse.verbose(2,"Trying User ID: %s", pass)
      self.tn3270:send_cursor(pass)
      self.tn3270:get_all_data()
      -- some systems require an enter after sending a valid user ID
      if self.tn3270:find("***") then
        self.tn3270:send_enter()
        self.tn3270:get_all_data()
      end
    end


    stdnse.debug(2,"Screen Recieved for User ID: %s", pass)
    self.tn3270:get_screen_debug(2)
    if self.tn3270:find('not authorized to use TSO') then -- invalid user ID
      return false,  brute.Error:new( "Incorrect User ID" )
    elseif ( self.tn3270:find('NO USER APPLID AVAILABLE') ) or
            ( self.tn3270:isClear() ) or (not self.tn3270:find('TSO/E LOGON') ) then
      local err = brute.Error:new( "TSO Unavailable" )
        -- This error occurs on too many concurrent application requests it
        -- should be temporary. If not, the script errors and less threads should be used.
      err:setRetry( true )
      return false, err
    else
      stdnse.verbose("Valid TSO User ID: %s", string.upper(pass))
      return true, creds.Account:new("TSO User",string.upper(pass), " Valid User ID")
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
  stdnse.debug("Getting to TSO")
  local run = stdnse.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    tn:send_cursor(run[i])
    tn:get_all_data()
  end
  tn:get_screen_debug(2)

  if tn:find("ENTER USERID") or tn:find("TSO/E LOGON")  then
    tso = true
    -- Patch OA44855 removed the ability to enumerator users
    -- we check for that here
    tn:send_cursor("notreal")
    tn:get_all_data()
    if tn:find("IKJ56476I ENTER PASSWORD") then
      return false, "Could not enumerate. PASSWORDPREPROMPT is set to ON."
    end
  end

  if tn:find("***") then
    secprod = "TopSecret/ACF2"
  end

  tn:send_pf(3)
  tn:disconnect()
  return tso, secprod, "Could not get to TSO. Try --script-args=tso-enum.commands='logon applid(tso)'. Aborting."
end

-- Filter iterator for unpwdb
-- TSO is limited to 7 alpha numeric and @, #, $ and can't start with a number
-- pattern:
--  ^%D     = The first char must NOT be a digit
-- [%w@#%$] = All letters including the special chars @, #, and $.
local valid_name = function(x)
  return (string.len(x) <= 7 and string.match(x,"^%D+[%w@#%$]"))
end

action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') or "tso"
  local tsotst, secprod, err = tso_test(host, port, commands)
  if tsotst then
    local options = { key1 = commands }
    stdnse.debug("Starting TSO User ID Enumeration")
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    engine:setPasswordIterator(unpwdb.filter_iterator(brute.usernames_iterator(),valid_name))
    engine.options.passonly = true
    engine.options:setTitle("TSO User ID")
    local status, result = engine:start()
    port.version.extrainfo = "Security: " .. secprod
    nmap.set_port_version(host, port)
    return result
  else
    return err
  end

end
