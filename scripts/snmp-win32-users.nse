local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local table = require "table"

description = [[
Attempts to enumerate Windows user accounts through SNMP
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-win32-users <target>
-- @output
-- | snmp-win32-users:
-- |   Administrator
-- |   Guest
-- |   IUSR_EDUSRV011
-- |   IWAM_EDUSRV011
-- |   SUPPORT_388945a0
-- |   Tomcat
-- |   db2admin
-- |   ldaptest
-- |_  patrik
-- @xmloutput
-- <elem>Administrator</elem>
-- <elem>Guest</elem>
-- <elem>IUSR_EDUSRV011</elem>
-- <elem>IWAM_EDUSRV011</elem>
-- <elem>SUPPORT_388945a0</elem>
-- <elem>Tomcat</elem>
-- <elem>db2admin</elem>
-- <elem>ldaptest</elem>
-- <elem>patrik</elem>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "auth", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occur if a mib did not exist
-- Revised 04/11/2010 - v0.3 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table with just the values
local function process_answer( tbl )

  local new_tab = {}

  for _, v in ipairs( tbl ) do
    table.insert( new_tab, v.value )
  end

  table.sort( new_tab )

  return new_tab

end

action = function(host, port)

  local snmpoid = "1.3.6.1.4.1.77.1.2.25"
  local users = {}
  local status

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  status, users = snmpHelper:walk( snmpoid )

  if( not(status) ) then
    return
  end

  users = process_answer( users )

  if ( users == nil ) or ( #users == 0 ) then
    return
  end

  nmap.set_port_state(host, port, "open")

  return users
end

