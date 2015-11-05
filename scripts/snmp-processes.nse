local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Attempts to enumerate running processes through SNMP.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-processes <target>
-- @output
-- | snmp-processes:
-- |   1:
-- |     Name: System Idle Process
-- |   4:
-- |     Name: System
-- |   256:
-- |     Name: smss.exe
-- |     Path: \SystemRoot\System32\
-- |   308:
-- |     Name: csrss.exe
-- |     Path: C:\WINDOWS\system32\
-- |     Params: ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserS
-- |   332:
-- |     Name: winlogon.exe
-- |   380:
-- |     Name: services.exe
-- |     Path: C:\WINDOWS\system32\
-- |   392:
-- |     Name: lsass.exe
-- |_    Path: C:\WINDOWS\system32\
--
-- @xmloutput
-- <table key="1">
--   <elem key="Name">System Idle Process</elem>
-- </table>
-- <table key="4">
--   <elem key="Name">System</elem>
-- </table>
-- <table key="256">
--   <elem key="Name">smss.exe</elem>
--   <elem key="Path">\SystemRoot\System32\</elem>
-- </table>
-- <table key="308">
--   <elem key="Name">csrss.exe</elem>
--   <elem key="Path">C:\WINDOWS\system32\</elem>
--   <elem key="Params">ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserS</elem>
-- </table>
-- <table key="332">
--   <elem key="Name">winlogon.exe</elem>
-- </table>
-- <table key="380">
--   <elem key="Name">services.exe</elem>
--   <elem key="Path">C:\WINDOWS\system32\</elem>
-- </table>
-- <table key="392">
--   <elem key="Name">lsass.exe</elem>
--   <elem key="Path">C:\WINDOWS\system32\</elem>
-- </table>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.4
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occur if a mib did not exist
-- Revised 01/19/2010 - v0.3 - removed debugging output and renamed file
-- Revised 04/11/2010 - v0.4 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
function get_value_from_table( tbl, oid )

  for _, v in ipairs( tbl ) do
    if v.oid == oid then
      return v.value
    end
  end

  return nil
end

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl )

  local swrun_name = "1.3.6.1.2.1.25.4.2.1.2"
  local swrun_pid = "1.3.6.1.2.1.25.4.2.1.1"
  local swrun_path = "1.3.6.1.2.1.25.4.2.1.4"
  local swrun_params = "1.3.6.1.2.1.25.4.2.1.5"
  local new_tbl = stdnse.output_table()

  for _, v in ipairs( tbl ) do

    if ( v.oid:match("^" .. swrun_pid) ) then
      local item = stdnse.output_table()
      local objid = v.oid:gsub( "^" .. swrun_pid, swrun_name)
      local value = get_value_from_table( tbl, objid )

      if value then
        item["Name"] = value
      end

      objid = v.oid:gsub( "^" .. swrun_pid, swrun_path)
      value =  get_value_from_table( tbl, objid )

      if value and value:len() > 0 then
        item["Path"] = value
      end

      objid = v.oid:gsub( "^" .. swrun_pid, swrun_params)
      value = get_value_from_table( tbl, objid )

      if value and value:len() > 0 then
        item["Params"] = value
      end

      -- key (PID) must be a string for output to work.
      new_tbl[tostring(v.value)] = item
    end

  end

  return new_tbl

end


action = function(host, port)

  local data, snmpoid = nil, "1.3.6.1.2.1.25.4.2"
  local shares = {}
  local status

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  status, shares = snmpHelper:walk( snmpoid )

  if (not(status)) or ( shares == nil ) or ( #shares == 0 ) then
    return
  end

  shares = process_answer( shares )

  nmap.set_port_state(host, port, "open")

  return shares
end

