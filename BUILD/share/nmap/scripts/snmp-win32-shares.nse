local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Attempts to enumerate Windows Shares through SNMP.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-win32-shares <target>
-- @output
-- | snmp-win32-shares:
-- |   SYSVOL: C:\WINDOWS\sysvol\sysvol
-- |   NETLOGON: C:\WINDOWS\sysvol\sysvol\inspectit-labb.local\SCRIPTS
-- |_  Webapps: C:\Program Files\Apache Software Foundation\Tomcat 5.5\webapps\ROOT
--
-- @xmloutput
-- <elem key="SYSVOL">C:\WINDOWS\sysvol\sysvol</elem>
-- <elem key="NETLOGON">C:\WINDOWS\sysvol\sysvol\inspectit-labb.local\SCRIPTS</elem>
-- <elem key="Webapps">C:\Program Files\Apache Software Foundation\Tomcat 5.5\webapps\ROOT</elem>

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

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return an output table with (sharename, path) pairs
local function process_answer( tbl )

  local share_name = "1.3.6.1.4.1.77.1.2.27.1.1"
  local share_path = "1.3.6.1.4.1.77.1.2.27.1.2"
  local new_tbl = stdnse.output_table()

  for _, v in ipairs( tbl ) do

    if ( v.oid:match("^" .. share_name) ) then
      local objid = v.oid:gsub( "^" .. share_name, share_path)
      local path = get_value_from_table( tbl, objid )

      new_tbl[v.value] = path
    end

  end

  return new_tbl

end


action = function(host, port)

  local data, snmpoid = nil, "1.3.6.1.4.1.77.1.2.27"
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

