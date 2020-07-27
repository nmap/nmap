local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local table = require "table"

description = [[
Attempts to enumerate Windows services through SNMP.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-win32-services <target>
-- @output
-- | snmp-win32-services:
-- |   Apache Tomcat
-- |   Application Experience Lookup Service
-- |   Application Layer Gateway Service
-- |   Automatic Updates
-- |   COM+ Event System
-- |   COM+ System Application
-- |   Computer Browser
-- |   Cryptographic Services
-- |   DB2 - DB2COPY1 - DB2
-- |   DB2 Management Service (DB2COPY1)
-- |   DB2 Remote Command Server (DB2COPY1)
-- |   DB2DAS - DB2DAS00
-- |_  DCOM Server Process Launcher
-- @xmloutput
-- <elem>Apache Tomcat</elem>
-- <elem>Application Experience Lookup Service</elem>
-- <elem>Application Layer Gateway Service</elem>
-- <elem>Automatic Updates</elem>
-- <elem>COM+ Event System</elem>
-- <elem>COM+ System Application</elem>
-- <elem>Computer Browser</elem>
-- <elem>Cryptographic Services</elem>
-- <elem>DB2 - DB2COPY1 - DB2</elem>
-- <elem>DB2 Management Service (DB2COPY1)</elem>
-- <elem>DB2 Remote Command Server (DB2COPY1)</elem>
-- <elem>DB2DAS - DB2DAS00</elem>
-- <elem>DCOM Server Process Launcher</elem>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/19/2010 - v0.2 - fixed loop that would occur if a mib did not exist
-- Revised 04/11/2010 - v0.3 - moved snmp_walk to snmp library <patrik@cqure.net>


portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})


--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table containing just the values
local function process_answer( tbl )

  local new_tab = {}

  for _, v in ipairs( tbl ) do
    table.insert( new_tab, v.value )
  end

  table.sort( new_tab )

  return new_tab

end

action = function(host, port)

  local snmpoid = "1.3.6.1.4.1.77.1.2.3.1.1"
  local services = {}
  local status

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  status, services = snmpHelper:walk( snmpoid )

  if ( not(status) ) or ( services == nil ) or ( #services == 0 ) then
    return
  end

  services = process_answer(services)
  nmap.set_port_state(host, port, "open")

  return services
end

