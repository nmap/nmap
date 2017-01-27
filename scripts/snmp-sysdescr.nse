local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local string = require "string"
local stdnse = require "stdnse"

description = [[
Attempts to extract system information from an SNMP version 1 service.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-sysdescr <target>
--
-- @output
-- |  snmp-sysdescr: HP ETHERNET MULTI-ENVIRONMENT,ROM A.25.80,JETDIRECT,JD117,EEPROM V.28.22,CIDATE 08/09/2006
-- |_   System uptime: 28 days, 17:18:59 (248153900 timeticks)

author = "Thomas Buchanan"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"snmp-brute"}


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

---
-- Sends SNMP packets to host and reads responses
action = function(host, port)

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  -- build a SNMP v1 packet
  -- copied from packet capture of snmpget exchange
  -- get value: 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0)
  local status, response = snmpHelper:get({reqId=28428}, "1.3.6.1.2.1.1.1.0")

  if not status then
    return
  end

  -- since we got something back, the port is definitely open
  nmap.set_port_state(host, port, "open")

  local result = response and response[1] and response[1][1]

  -- build a SNMP v1 packet
  -- copied from packet capture of snmpget exchange
  -- get value: 1.3.6.1.2.1.1.3.0 (SNMPv2-MIB::sysUpTime.0)
  status, response = snmpHelper:get({reqId=28428}, "1.3.6.1.2.1.1.3.0")

  if not status then
    return result
  end

  local uptime = response and response[1] and response[1][1]
  if not uptime then
    return
  end

  result = result .. "\n" .. string.format("  System uptime: %s (%s timeticks)", stdnse.format_time(uptime, 100), tostring(uptime))

  return result
end

