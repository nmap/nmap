local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local io = require "io"
local nmap = require "nmap"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
TN3270 VTAM applications may have certain modes enabled, or may not handle error states properly.
To test for this we send AIDs (Action IDentifier keys) to the session and record the reaction. 
If it differs from the original screen it reports the change. Screenshots can be saved to txt
files.

There are 35 declared in AIDs in the tn3270 library as follows: 
'NO', 'QREPLY', 'ENTER', 'PF1', 'PF2', 'PF3', 'PF4', 'PF5', 'PF6',
'PF7', 'PF8', 'PF9', 'PF10', 'PF11', 'PF12', 'PF13', 'PF14', 'PF15',
'PF16', 'PF17', 'PF18', 'PF19', 'PF20', 'PF21', 'PF22', 'PF23', 'PF24',
'OICR', 'MSR_MHS', 'SELECT', 'PA1', 'PA2', 'PA3', 'CLEAR', 'SYSREQ'
]]

---
--@args aid-enum.aid the Action IDentifier to try. Default is all 35 AIDs.
--@args aid-enum.commands Commands in a semi-colon separated list needed
--  to access the application to test. Defaults to <code>nothing</code>.
--@args aid-enum.path Folder used to store valid transaction id 'screenshots'
--  Defaults to <code>None</code> and doesn't store anything.
--
--@usage
-- nmap --script aid-enum -p 23 <targets>
--
-- nmap --script aid-enum --script-args aid-enum.aid=PF1,
-- aid-enum.commands="exit;logon applid(logos)",
-- aid-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>
--
--@output
-- PORT   STATE SERVICE VERSION
-- 23/tcp open  tn3270  IBM Telnet TN3270 (TN3270E)
-- | aid-enum: 
-- |   NO:  The key you pressed is inactive\x00
-- |   QREPLY:  The key you pressed is inactive\x00
-- |   ENTER:  loooooooooooooooooooooooooool\x00
-- |   PA3:  The key you pressed is inactive\x00
-- |   CLEAR: 
-- |_  SYSREQ:  The key you pressed is inactive\x00
--
--@changelog
-- 2020-02-10 - Created aid-enum

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({23,992}, "tn3270")

--- Saves the Screen generated to disk
--
-- @param filename string containing the name and full path to the file
-- @param data contains the data
-- @return status true on success, false on failure
-- @return err string containing error message if status is false
local function save_screens( filename, data )
  local f = io.open( filename, "w")
  if not f then return false, ("Failed to open file (%s)"):format(filename) end
  if not(f:write(data)) then return false, ("Failed to write file (%s)"):format(filename) end
  f:close()
  return true
end

--- Compares two screens and returns the difference as a percentage
--
-- @param1 the original screen
-- @param2 the screen to compare to
local function screen_diff_percent( orig_screen, current_screen )
  if orig_screen == current_screen then return 100 end
  if #orig_screen == 0 or #current_screen == 0 then return 0 end
  local m = 1
  for i = 1 , #orig_screen do
    if orig_screen:byte(i) == current_screen:byte(i) then
      m = m + 1
    end
  end
  return (m/1920)*100
end


--- Compares two screens and returns the difference between those screens
--
-- @param1 the original screen
-- @param2 the screen to compare to
local function screen_diff_text(old, new)
  local spaces = 4
  local start, space_count, j
  local diff = ''
  i = 1
  while i <= #old do
    if old:sub(i,i) ~= new:sub(i,i) then
      start = i
      space_count = 0
      j = i
      i = i + 1
      while i <= #old or space_count <= spaces do
        if old:sub(i,i) == " " and new:sub(i,i) == " " then
          space_count = space_count + 1
        elseif old:sub(i,i) == new:sub(i,i) then
          break
        end
        i = i + 1
      end
      diff = diff .. " " .. new:sub(j,i)
    end
    i = i + 1
  end
  return diff
end

function correct_aid(aids,aid)
  for _, v in ipairs(aids) do
    if v == aid then
      return true
    end
  end
  return false
end


action = function(host, port)
  local aids = {'NO', 'QREPLY', 'ENTER', 'PF1', 'PF2', 'PF3', 'PF4', 'PF5', 'PF6',
                'PF7', 'PF8', 'PF9', 'PF10', 'PF11', 'PF12', 'PF13', 'PF14', 'PF15',
                'PF16', 'PF17', 'PF18', 'PF19', 'PF20', 'PF21', 'PF22', 'PF23', 'PF24',
                'OICR', 'MSR_MHS', 'SELECT', 'PA1', 'PA2', 'PA3', 'CLEAR', 'SYSREQ' }
  local aid = stdnse.get_script_args(SCRIPT_NAME .. '.aid') or nil
  local path = stdnse.get_script_args(SCRIPT_NAME .. '.path') or nil-- Folder for screen grabs
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') -- Commands to send to get to Application

  if aid ~= nil and correct_aid(aids, aid) == false then
    return "Error: " .. aid .. " invalid. " .. SCRIPT_NAME .. '.aid' .. " must be one of: NO, QREPLY, ENTER, PF1, PF2, PF3, PF4, PF5, PF6, PF7, PF8, PF9, PF10, PF11, PF12, PF13, PF14, PF15, PF16, PF17, PF18, PF19, PF20, PF21, PF22, PF23, PF24, OICR, MSR_MHS, SELECT, PA1, PA2, PA3, CLEAR, SYSREQ"
  end
  local out = stdnse.output_table()

  if aid ~= nil then
    aids = {aid}
  end

  for i, aid in ipairs(aids) do
    stdnse.verbose(2,"Trying AID (#%s of %s): %s",i,#aids,aid )
    local t = tn3270.Telnet:new()
    local status, err = t:initiate(host,port)
    if not status then
      stdnse.debug("Could not initiate TN3270: %s", err )
      return 
    else
      if commands then
        local run = stringaux.strsplit(";%s*", commands)
        for i = 1, #run do
          stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
          t:send_cursor(run[i])
          t:get_all_data()
          t:get_screen_debug(2)
        end
      end
      status = t:get_all_data()
      local previous_screen = t:get_screen_raw()
      -- At this point we're connected and at the appplication we want to test
      -- Now we send the AID and then record the screen
      t:send_aid(aid)
      t:get_all_data()
      t:get_screen_debug(2)
      local current_screen = t:get_screen_raw()
      local diff_percent = screen_diff_percent(previous_screen, current_screen)
      if 100 - diff_percent > 0 then
        local diff = screen_diff_text(previous_screen, current_screen)
        if #diff <= 81 then
          -- if its longer than a line just note it
          -- if users want they can use the path option to save it
          stdnse.verbose("Screen Changed for AID ".. aid ..":" .. diff)
          out[aid] = diff
        else
          stdnse.verbose("Screen Changed for AID ".. aid .. t:get_screen():match( "^%s*(.-)%s*$" ))
          out[aid] = t:get_screen():match( "^%s*(.-)%s*$" )
        end
        if path ~= nil then
          stdnse.verbose(2,"Writting screen to: %s", path..aid..".txt")
          local status, err = save_screens(path..aid..".txt",t:get_screen())
          if not status then
            stdnse.verbose(2,"Failed writting screen to: %s", path..aid..".txt")
          end
        end
      end
    end
  end
  return out

end
