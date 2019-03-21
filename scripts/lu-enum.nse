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
Attempts to enumerate Logical Units (LU) of TN3270E servers.

When connecting to a TN3270E server you are assigned a Logical Unit (LU) or you can tell
the TN3270E server which LU you'd like to use. Typically TN3270E servers are configured to 
give you an LU from a pool of LUs. They can also have LUs set to take you to a specific
application. This script attempts to guess valid LUs that bypass the default LUs you are
assigned. For example, if a TN3270E server sends you straight to TPX you could use this
script to find LUs that take you to TSO, CICS, etc.
]]

---
--@args lulist Path to list of Logical Units to test.
--  Defaults the initial Logical Unit TN3270E provides, replacing the 
--  last two characters with <code>00-99</code>.
--@args lu-enum.path Folder used to store valid logical unit 'screenshots'
--  Defaults to <code>None</code> and doesn't store anything. This stores 
--  all valid logical units.
--@usage
-- nmap --script lu-enum -p 23 <targets>
--
--@usage
-- nmap --script lu-enum --script-args lulist=lus.txt,
-- lu-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>
--
--@output
-- PORT     STATE SERVICE REASON  VERSION
-- 23/tcp   open  tn3270  syn-ack IBM Telnet TN3270 (TN3270E)
-- | lu-enum: 
-- |   Logical Units: 
-- |     LU:BSLVLU69 - Valid credentials
-- |_  Statistics: Performed 7 guesses in 7 seconds, average tps: 1.0
-- 
-- @changelog
-- 2019-02-04 - v0.1 - created by Soldier of Fortran

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({23,992}, "tn3270")

--- Saves the TN3270E terminal screen to disk
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
local function screen_diff( orig_screen, current_screen )
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
    return true
  end,
  disconnect = function( self )
    self.tn3270:disconnect()
    self.tn3270 = nil
  end,
  login = function (self, user, pass) -- pass is actually the username we want to try
    local path = self.options['path']
    local original = self.options['no_lu']
    local threshold = 90
    stdnse.verbose(2,"Trying Logical Unit: %s", pass)
    self.tn3270:set_lu(pass)
    local status, err = self.tn3270:initiate(self.host,self.port)
    if not status then
      stdnse.debug(2,"Could not initiate TN3270: %s", err )
      stdnse.verbose(2, "Invalid LU: %s",string.upper(pass))
      return false,  brute.Error:new( "Invalid Logical Unit" )
    end
    self.tn3270:get_all_data()
    self.tn3270:get_screen_debug(2)
    if path ~= nil then
      stdnse.verbose(2,"Writting screen to: %s", path..string.upper(pass)..".txt")
      local status, err = save_screens(path..string.upper(pass)..".txt",self.tn3270:get_screen())
      if not status then
        stdnse.verbose(2,"Failed writting screen to: %s", path..string.upper(pass)..".txt")
      end
    end

    stdnse.debug(3, "compare results: %s ", tostring(screen_diff(original, self.tn3270:get_screen_raw())))
    if screen_diff(original, self.tn3270:get_screen_raw()) > threshold then
      stdnse.verbose(2,'Same Screen for LU: %s',string.upper(pass))
      return false,  brute.Error:new( "Invalid Logical Unit" )
    else
      stdnse.verbose(2,"Valid Logical Unit: %s",string.upper(pass))
      return true, creds.Account:new("LU", string.upper(pass), creds.State.VALID)
    end
  end
}

--- Tests the target to see if we can connect with TN3270E
--
-- @param host host NSE object
-- @param port port NSE object
-- @return status true on success, false on failure
local function lu_test( host, port )
  local tn = tn3270.Telnet:new()
  local status, err = tn:initiate(host,port)
  
  if not status then
    stdnse.debug(1,"[lu_test] Could not initiate TN3270: %s", err )
    return false
  end

  stdnse.debug(2,"[lu_test] Displaying initial TN3270 Screen:")
  tn:get_screen_debug(2) -- prints TN3270 screen to debug
  if tn.state == tn.TN3270E_DATA then -- Could make a function in the library 'istn3270e'
    stdnse.debug(1,"[lu_test] Orig screen: %s", tn:get_screen_raw())
    return true, tn:get_lu(), tn:get_screen_raw()
  else 
    return false, 'Not in TN3270E Mode. LU not supported.', ''
  end

end

-- Checks if it's a valid Logical Unit name
local valid_lu = function(x)
  return (string.len(x) <= 8 and string.match(x,"[%w@#%$]"))
end

-- iterator function
function iter(t)
  local i, val
  return function()
    i, val = next(t, i)
    return val
  end
end

action = function(host, port)
  local lu_id_file = stdnse.get_script_args("lulist")
  local path = stdnse.get_script_args(SCRIPT_NAME .. '.path') -- Folder for screen grabs
  local logical_units = {}
  lu_id_file = ((lu_id_file and nmap.fetchfile(lu_id_file)) or lu_id_file) 

  local status, lu, orig_screen = lu_test( host, port )
  if status then
      
    
    if not lu_id_file then
      -- we have to do this here because we don't have an LU to use for the template until now
      stdnse.debug(3, "No LU list provided, auto generating a list using template: %s##", lu:sub(1, (#lu-2)))
      for i=1,99 do
        table.insert(logical_units, lu:sub(1, (#lu-2)) .. string.format("%02d", i))
        end
    else 
      for l in io.lines(lu_id_file) do
        local cleaned_line = string.gsub(l,"[\r\n]","")
        if not cleaned_line:match("#!comment:") then
          table.insert(logical_units, cleaned_line)
        end
      end
    end
    
    
    -- Make sure we pass the original screen we got to the brute 
    local options = { no_lu = orig_screen, path = path }
    if path ~= nil then stdnse.verbose(2,"Saving Screenshots to: %s", path) end
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    engine:setPasswordIterator(unpwdb.filter_iterator(iter(logical_units), valid_lu))
    engine.options.passonly = true
    engine.options:setTitle("Logical Units")
    local status, result = engine:start()
    return result
  else
    stdnse.debug(1,"Not in TN3270E mode, LU not supported.")
    return lu
  end

end
