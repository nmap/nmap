local stdnse = require "stdnse"
local shortport = require "shortport"
local tn3270 = require "tn3270"

description = [[
Connects to a tn3270 'server' and returns the screen.

Hidden fields will be listed below the screen with (row, col) coordinates.
]]

---
-- @usage
-- nmap --script tn3270-info,tn3270_screen <host>
--
-- @output
-- PORT     STATE  SERVICE         VERSION
-- 23/tcp   open   tn3270          Telnet TN3270
-- | tn3270-screen:
-- |  screen:
-- |  Mainframe Operating System                              z/OS V1.6
-- |          FFFFF  AAA  N   N      DDDD  EEEEE      ZZZZZ H   H  III
-- |          F     A   A NN  N      D   D E             Z  H   H   I
-- |          FFFF  AAAAA N N N      D   D EEEE         Z   HHHHH   I
-- |          F     A   A N  NN      D   D E           Z    H   H   I
-- |          F     A   A N   N      DDDD  EEEEE      ZZZZZ H   H  III
-- |
-- |                         ZZZZZ      / OOOOO  SSSS
-- |                            Z      /  O   O S
-- |                           Z      /   O   O  SSS
-- |                          Z      /    O   O     S
-- |                         ZZZZZ  /     OOOOO SSSS
-- |
-- |                   Welcome to Fan DeZhi Mainframe System!
-- |
-- |                       Support: http://zos.efglobe.com
-- |          TSO      - Logon to TSO/ISPF        NETVIEW  - Netview System
-- |          CICS     - CICS System              NVAS     - Netview Access
-- |          IMS      - IMS System               AOF      - Netview Automation
-- |
-- | Enter your choice==>
-- | Hi! Enter one of above commands in red.
-- |
-- |_Your IP(10.10.10.375   :64199), SNA LU(        )       05/30/15 13:33:37
--
-- @args tn3270-screen.commands a semi-colon separated list of commands you want to
--                       issue before printing the screen
--
--
-- @changelog
-- 2015-05-30 - v0.1 - created by Soldier of Fortran
-- 2015-11-14 - v0.2 - added commands argument
--

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service({23,992}, {"tn3270"})

local hidden_field_mt = {
  __tostring = function(t)
    return ("(%d, %d): %s"):format(t.row, t.col, t.field)
  end,
}

action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands')
  local t = tn3270.Telnet:new()
  local status, err = t:initiate(host,port)
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return
  else
    if commands then
      local run = stdnse.strsplit(";%s*", commands)
      for i = 1, #run do
        stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
        t:send_cursor(run[i])
        t:get_all_data()
        t:get_screen_debug(2)
      end
    end
    status = t:get_all_data()
    local hidden
    if t:any_hidden() then
      hidden = {}
      local hidden_buggers = t:hidden_fields()
      local hidden_locs = t:hidden_fields_location()
      for i = 1, #hidden_buggers do
        local j = i*2 - 1
        local field = {
          field = hidden_buggers[i],
          row = t:BA_TO_ROW(hidden_locs[j]),
          col = t:BA_TO_COL(hidden_locs[j]),
        }
        setmetatable(field, hidden_field_mt)
        hidden[i] = field
      end
    end
    local out = stdnse.output_table()
    out.screen = t:get_screen()
    out["hidden fields"] = hidden
    return out
  end
end
