local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate installed software through SNMP.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-win32-software <target>
-- @output
-- | snmp-win32-software:
-- |   Apache Tomcat 5.5 (remove only); 2007-09-15T15:13:18
-- |   Microsoft Internationalized Domain Names Mitigation APIs; 2007-09-15T15:13:18
-- |   Security Update for Windows Media Player (KB911564); 2007-09-15T15:13:18
-- |   Security Update for Windows Server 2003 (KB924667-v2); 2007-09-15T15:13:18
-- |   Security Update for Windows Media Player 6.4 (KB925398); 2007-09-15T15:13:18
-- |   Security Update for Windows Server 2003 (KB925902); 2007-09-15T15:13:18
-- |_  Windows Internet Explorer 7; 2007-09-15T15:13:18
--
-- @xmloutput
-- <table>
--   <elem key="name">Apache Tomcat 5.5 (remove only)</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Microsoft Internationalized Domain Names Mitigation APIs</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Security Update for Windows Media Player (KB911564)</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Security Update for Windows Server 2003 (KB924667-v2)</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Security Update for Windows Media Player 6.4 (KB925398)</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Security Update for Windows Server 2003 (KB925902)</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>
-- <table>
--   <elem key="name">Windows Internet Explorer 7</elem>
--   <elem key="install_date">2007-09-15T15:13:18</elem>
-- </table>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occur if a mib did not exist
-- Revised 04/11/2010 - v0.3 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
local function get_value_from_table( tbl, oid )

  for _, v in ipairs( tbl ) do
    if v.oid == oid then
      return v.value
    end
  end

  return nil
end

local date_xlate = {
  year = 2,
  month = 3,
  day = 4,
  hour = 5,
  min = 6,
  sec = 7
}

-- translate date parts to positional indices for stdnse.format_timestamp
local date_metatab = {
  __index = function (t, k)
    return t[date_xlate[k]]
  end
}

local sw_metatab = {
  __tostring = function (t)
    return ("%s; %s"):format(t.name , t.install_date)
  end
}

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
local function process_answer( tbl )

  local sw_name = "^1.3.6.1.2.1.25.6.3.1.2"
  local sw_date = "1.3.6.1.2.1.25.6.3.1.5"
  local new_tbl = {}

  for _, v in ipairs( tbl ) do

    if ( v.oid:match(sw_name) ) then
      local objid = v.oid:gsub(sw_name, sw_date)
      local install_date = get_value_from_table( tbl, objid )
      local install_date_tab = { bin.unpack( ">SCCCCC", install_date ) }
      setmetatable(install_date_tab, date_metatab)

      local sw_item = {
        ["name"] = v.value,
        ["install_date"] = stdnse.format_timestamp(install_date_tab)
      }

      setmetatable(sw_item, sw_metatab)
      table.insert( new_tbl, sw_item )
    end

  end

  table.sort( new_tbl, function(a, b) return a.name < b.name end )
  return new_tbl

end


action = function(host, port)

  local data, snmpoid = nil, "1.3.6.1.2.1.25.6.3.1"
  local sw = {}
  local status

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  status, sw = snmpHelper:walk( snmpoid )

  if ( not(status) ) or ( sw == nil ) or ( #sw == 0 ) then
    return
  end

  sw = process_answer( sw )

  nmap.set_port_state(host, port, "open")

  return sw
end

