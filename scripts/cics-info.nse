local nmap      = require "nmap"
local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local table     = require "table"
local string   = require "string"


description = [[
Using the CICS transaction CEMT, this script attempts to gather information
about the current CICS transaction server region. It gathers OS information,
Datasets (files), transactions and user ids. Based on CICSpwn script by
Ayoub ELAASSAL.
]]

---
-- @args cics-info.commands Command used to access cics. Default is <code>cics</code>
-- @args cics-info.cemt CICS Transaction ID to be used. Default is <code>CEMT</code>
-- @args cics-info.trans Instead of gathering all transaction IDs supplying a name here
--                       will make the script only look up one transaction ID
-- @args cics-info.user Username to use if access to CEMT requires authentication
-- @args cics-info.pass Password to use if access to CEMT requires authentication
--
-- @usage
-- nmap --script=cics-info -p 23 <targets>
--
-- nmap --script=cics-info --script-args cics-info.commands='logon applid(coolcics)',
-- cics-info.user=test,cics-info.pass=test,cics-info.cemt='ZEMT',
-- cics-info.trans=CICA -p 23 <targets>
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 23/tcp open  tn3270  IBM Telnet TN3270 (TN3270E)
-- | cics-info:
-- |   Security: Disabled
-- |   System:
-- |     z/OS Version: 02.01.00
-- |     CICS Version: 05.02.00
-- |     System ID: CICS
-- |     Application ID: CICSFAKE
-- |     Default User: USERCICS
-- |   Datasets:
-- |     CICS.FILEA
-- |     HLQ123.CICS.DFHCSD
-- |     HLQ123.CICS.DFHLRQ
-- |   Libraries:
-- |     HLQ123.CICS.SDFHLOAD
-- |   Users:
-- |     USERCICS
-- |   Transaction / Program:
-- |     AADD / DFH$AALL
-- |     ABRW / DFH$ABRW
-- |     AINQ / DFH$AALL
-- |     AMNU / DFH$AMNU
-- |     AORD / DFH$AREN
-- |     AORQ / DFH$ACOM
-- |     AREP / DFH$AREP
-- |     AUPD / DFH$AALL
-- |     CADP / DFHDPLU
-- ...
-- |     CEDX / DFHEDFP
-- |     CEGN / DFHCEGN
-- |     CEHP / DFHCHS
-- |     CEHS / DFHCHS
-- |     CEJR / DFHEJITL
-- |     CEMN / DFHCEMNA
-- |     CEMT / DFHEMTP
-- |     CEOT / DFHEOTP
-- |     CXRT / DFHCRT
-- |     DSNC / DFHD2CM1

-- @changelog
-- 2017-01-30 - v0.1 - created by Soldier of Fortran

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = shortport.port_or_service({23,992}, "tn3270")



--- Gathers CICS transaction server information
--
-- @param host host NSE object
-- @param port port NSE object
-- @param user CICS userID
-- @param pass CICS userID password
-- @param commands optional script-args of commands to use to get to CICS
-- @param cemt transaction ID to use instead of CEMT
-- @param trans transaction ID to check instead of gathering all
-- @return Status boolean true if CICS was detected.
-- @return Table of information or error message

local function cics_info( host, port, commands, user, pass, cemt, trans )
  stdnse.debug("Checking for CICS")
  local tn = tn3270.Telnet:new()
  local status, err = tn:initiate(host,port)
  local msg = 'Unable to get to CICS'
  local more = true
  local count = 1
  local results = stdnse.output_table()
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return false, msg
  end
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  stdnse.debug("Getting to CICS")
  local run = stdnse.strsplit(";%s*", commands)
  for i = 1, #run do
    stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
    tn:send_cursor(run[i])
    tn:get_all_data()
    tn:get_screen_debug(2)
  end
  tn:get_all_data()
  tn:get_screen_debug(2) -- for debug purposes
  -- we should technically be at CICS. So we send:
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
    -- this loop continues to try getting out of CESL 6 times. If it can't
    -- then we probably weren't in CICS to begin with.
    if tn:find("Signon") then
      stdnse.debug(2,"Found CESL/CESN 'Signon' sending PF3")
      tn:send_pf(3)
      tn:get_all_data()
    end
    tn:get_all_data()
    stdnse.debug(2,"Clearing the Screen")
    tn:send_clear()
    tn:get_all_data()
    tn:get_screen_debug(2)
    count = count + 1
  end
  if count == 6 then
    return false, msg
  end
  stdnse.debug(2,"Sending CESF (CICS Default Sign-off)")
  tn:send_cursor('CESF')
  tn:get_all_data()
  if tn:isClear() then
    tn:get_all_data(1000)
  end
  tn:get_screen_debug(2)

  if not tn:find('off is complete.') then
    return false, 'Unable to get to CICS. Try --script-args cics-info.commands="logon applid(<applid>)"'
  end


  if user and pass then -- We're doing authenticated CICS testing now baby!
    stdnse.verbose(2,'Logging in with %s / %s for auth testing', user, pass)
    tn:send_clear()
    tn:get_all_data()
    tn:get_screen_debug(2)
    tn:send_cursor('CESN')
    tn:get_all_data()
    tn:get_screen_debug(2)
    local fields = tn:writeable() -- Get the writeable field areas
    local user_loc = {fields[1][1],user}   -- This is the 'UserID:' field
    local pass_loc = {fields[3][1],pass}   -- This is the 'Password:' field ([2] is a group ID)
    stdnse.verbose('Trying CICS: %s : %s', user, pass)
    tn:send_locations({user_loc,pass_loc})
    tn:get_all_data()
    stdnse.debug(2,"Screen Received for User ID: %s / %s", user, pass)
    tn:get_screen_debug(2)
    count = 1
    while not tn:find('DFHCE3549') and count < 6 do
        tn:get_all_data(1000) -- loop for 6 seconds
        tn:get_screen_debug(2)
        count = count + 1
    end
    if not tn:find('DFHCE3549') then
        msg = 'Unable to access CICS with User: '..user..' / Pass: '..pass
        return false, msg
    end
  end
  -- By now it's time to start trying to gather information
  tn:send_clear()
  tn:get_all_data()
  tn:send_cursor('CESN')
  tn:get_all_data()
  tn:get_screen_debug(2)

  results["Security"] = tn:find('DFHCE3547') and "Enabled" or "Disabled"
  stdnse.debug(2,"Sending F3")
  tn:send_pf(3)
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.debug(2,"Sending 'Clear Screen'")
  tn:send_clear()
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.verbose(2,"Sending 'CEMT INQUIRE SYSTEM'")
  tn:send_cursor('CEMT INQUIRE SYSTEM')
  tn:get_all_data()
  tn:get_screen_debug(2)
  if tn:find('DFHAC2002') then
    results["Error"] = 'CEMT Access Denied.'
    return true, results
  elseif tn:find('NOT AUTHORIZED') then
    results["System"] = "CEMT 'INQUIRE SYSTEM' Access Denied."
  else
    local sysresults = stdnse.output_table()
    local l1, l2 = tn:find('Oslevel')
    local oslevel = tn:get_screen_raw():sub(l2+2,l2+7)
    l1, l2 = tn:find('Cicstslevel')
    local cicstslevel = tn:get_screen_raw():sub(l2+2,l2+7)
    l1, l2 = tn:find('Dfltuser')
    local Dfltuser = tn:get_screen_raw():sub(l2+2,l2+10)
    local Dfltuser_len = Dfltuser:find(')')
    l1, l2 = tn:find('Db2conn')
    local Db2conn = tn:get_screen_raw():sub(l2+2,l2+10)
    local Db2conn_len = Db2conn:find(')')
    l1, l2 = tn:find('Mqconn')
    local Mqconn = tn:get_screen_raw():sub(l2+2,l2+10)
    local Mqconn_len = Mqconn:find(')')
    l1, l2 = tn:find('SYSID')
    local SYSID = tn:get_screen_raw():sub(l2+2,l2+10)
    local SYSID_len = SYSID:find('\00')
    l1, l2 = tn:find('APPLID')
    local APPLID = tn:get_screen_raw():sub(l2+2,l2+10)
    local APPLID_len = APPLID:find('\00')
    sysresults["z/OS Version"] = ("%s.%s.%s"):format( oslevel:sub(1,2),oslevel:sub(3,4),oslevel:sub(5,6) )
    sysresults["CICS Version"] = ("%s.%s.%s"):format( cicstslevel:sub(1,2),cicstslevel:sub(3,4),cicstslevel:sub(5,6) )
    sysresults["System ID"] = SYSID:sub(1,SYSID_len-1)
    sysresults["Application ID"] = APPLID:sub(1,APPLID_len-1)
    sysresults["Default User"] = Dfltuser:sub(1,Dfltuser_len-1)
    if Db2conn_len > 1 then
      sysresults["DB2 Connection"] = Db2conn:sub(1,Db2conn_len-1)
    end
    if Mqconn_len > 1 then
      sysresults["MQ Connection"] = Mqconn:sub(1,Mqconn_len-1)
    end
    results["System"] = sysresults
  end -- Done with INQUIRE SYSTEM

  stdnse.debug(2,"Sending F3")
  tn:send_pf(3)
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.debug(2,"Sending 'Clear Screen'")
  tn:send_clear()
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.verbose(2,"Sending 'CEMT INQUIRE DSNAME'")
  tn:send_cursor('CEMT INQUIRE DSNAME')
  tn:get_all_data()
  tn:get_screen_debug(2)

  if tn:find('NOT AUTHORIZED') then
    results["Datasets"] = "CEMT 'INQUIRE DSNAME' Access Denied."
  else
    local datasets = {}
    while more do
      more = false
      for line in tn:get_screen():gmatch("[^\r\n]+") do
        if line:find('Dsn') then
          table.insert(datasets,line:sub(line:find('%(')+1, line:find(')')-1):match( "(.-)%s*$" ))
          if count >= 9 and line:find('+') then
            more = true
            count = 1
            stdnse.debug(2,"Sending F11")
            tn:send_pf(11)
            tn:get_all_data()
            tn:get_screen_debug(2)
          else
            count = count + 1
          end
        end
      end
    end
    results["Datasets"] = datasets
  end -- Done with DSNAME

  stdnse.debug(2,"Sending F3")
  tn:send_pf(3)
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.debug(2,"Sending 'Clear Screen'")
  tn:send_clear()
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.verbose(2,"Sending 'CEMT INQUIRE LIBRARY'")
  tn:send_cursor('CEMT INQUIRE LIBRARY')
  tn:get_all_data()
  tn:get_screen_debug(2)

  if tn:find('NOT AUTHORIZED') then
    results["Libraries"] = "CEMT 'INQUIRE LIBRARY' Access Denied."
  else
    local libraries = {}
    for line in tn:get_screen():gmatch("[^\r\n]+") do
      if line:find('Dsname') then
        table.insert(libraries,line:sub(line:find('%(')+1, line:find(')')-1):match( "(.-)%s*$" ))
      end
    end
    results["Libraries"] = libraries
  end -- Done with Library

  stdnse.debug(2,"Sending F3")
  tn:send_pf(3)
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.debug(2,"Sending 'Clear Screen'")
  tn:send_clear()
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.verbose(2,"Sending 'CEMT INQUIRE TASK'")
  tn:send_cursor('CEMT INQUIRE TASK')
  tn:get_all_data()
  tn:get_screen_debug(2)

  if tn:find('NOT AUTHORIZED') then
    results["Users"] = "CEMT 'INQUIRE TASK' Access Denied."
  else
    count = 1
    more = true
    local users = {}
    while more do
      more = false
      for line in tn:get_screen():gmatch("[^\r\n]+") do
        if line:find('Use') then
          table.insert(users,line:sub(line:find('Use')+4, line:find(')',line:find('Use'))-1):match( "(.-)%s*$" ))
          if count >= 9 and line:find('+') then
            more = true
            count = 1
            stdnse.debug(2,"Sending F11")
            tn:send_pf(11)
            tn:get_all_data()
            tn:get_screen_debug(2)
          else
            count = count + 1
          end
        end
      end
    end
    results["Users"] = users
  end -- End of TASK

  stdnse.debug(2,"Sending F3")
  tn:send_pf(3)
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.debug(2,"Sending 'Clear Screen'")
  tn:send_clear()
  tn:get_all_data()
  tn:get_screen_debug(2)
  stdnse.verbose(2,"Sending 'CEMT INQUIRE TRANSACTION(".. trans ..") en'")
  tn:send_cursor('CEMT INQUIRE TRANSACTION('.. trans ..') en')
  tn:get_all_data()
  tn:get_screen_debug(2)

  if tn:find('NOT AUTHORIZED') then
    results["Transaction / Program"] = "CEMT 'INQUIRE TRANSACION' Access Denied."
  else
    local transactions = {}
    count = 1
    more = true
    local tra, pro = ''
    while more do
      more = false
      for line in tn:get_screen():gmatch("[^\r\n]+") do
        if line:find('Tra%(') then
          tra = line:sub(line:find('%(')+1,line:find(')')-1)
          pro = line:sub(line:find('Pro%(')+4,line:find(')',line:find('Pro%('))-1)
          table.insert(transactions,tra..' / '..pro)
          if count >= 9 and line:find('+') then
            more = true
            count = 1
            stdnse.debug(2,"Sending F11")
            tn:send_pf(11)
            tn:get_all_data()
            tn:get_screen_debug(2)
          else
            count = count + 1
          end
        end
      end
    end
    results["Transaction / Program"] = transactions
  end -- Done with Transaction IDs
  tn:disconnect()
  return true, results
end


action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') or 'cics'-- VTAM commands/macros to get to CICS
  local username = stdnse.get_script_args(SCRIPT_NAME .. '.user') or nil
  local password = stdnse.get_script_args(SCRIPT_NAME .. '.pass') or nil
  if (username or password) and not (username and password) then
    stdnse.verbose1("Both 'user' and 'pass' are required for CICS auth")
  end
  local CEMT = stdnse.get_script_args(SCRIPT_NAME .. '.cemt') or 'cemt' -- to supply a different transaction ID if they've changed it
  local transaction = stdnse.get_script_args(SCRIPT_NAME .. '.trans') or '*'
  local status, results = cics_info(host, port, commands, username, password, CEMT, transaction)
  -- Report results. Only report an error if
  -- script args were set or the service is definitely TN3270
  if status or username or password or port.service == "tn3270" then
    return results
  end
end
