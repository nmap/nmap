local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Attempts to enumerate Huawei / HP/H3C Locally Defined Users through the
hh3c-user.mib OID

For devices running software released pre-Oct 2012 only an SNMP read-only
string is required to access the OID. Otherwise a read-write string is
required.

Output is 'username - password - level: {0|1|2|3}'

Password may be in cleartext, ciphertext or sha256
Levels are from 0 to 3 with 0 being the lowest security level

https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03515685
http://grutztopia.jingojango.net/2012/10/hph3c-and-huawei-snmp-weak-access-to.html
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-hh3c-logins --script-args creds.snmp=:<community> <target>
--
-- @output
-- | snmp-hh3c-logins:
-- |   users:
-- |     admin - admin - level: 3
-- |_    h3c - h3capadmin - level 0
--
-- @xmloutput
-- <table>
--   <elem key="password">admin<elem>
--   <elem key="username">admin</elem>
--   <elem key="level">3</elem>
-- </table>
-- <table>
--   <elem key="password">h3capadmin<elem>
--   <elem key="username">h3c</elem>
--   <elem key="level">0</elem>
-- </table>

author = "Kurt Grutzmacher"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 10/01/2012 - v0.1 - created via modifying other walk scripts
-- Updated 10/25/2012 - v0.2 - bugfixes and better output per NSE standards
-- Updated 11/08/2012 - v0.3 - added xmloutput


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
-- @return <code>stdnse.output_table</code> formatted table
function process_answer( tbl )

  -- h3c-user MIB OIDs (oldoid)
  local h3cUserName = "1.3.6.1.4.1.2011.10.2.12.1.1.1.1"
  local h3cUserPassword = "1.3.6.1.4.1.2011.10.2.12.1.1.1.2"
  local h3cUserLevel = "1.3.6.1.4.1.2011.10.2.12.1.1.1.4"
  local h3cUserState = "1.3.6.1.4.1.2011.10.2.12.1.1.1.5"

  -- hh3c-user MIB OIDs (newoid)
  local hh3cUserName = "1.3.6.1.4.1.25506.2.12.1.1.1.1"
  local hh3cUserPassword = "1.3.6.1.4.1.25506.2.12.1.1.1.2"
  local hh3cUserLevel = "1.3.6.1.4.1.25506.2.12.1.1.1.4"
  local hh3cUserState = "1.3.6.1.4.1.25506.2.12.1.1.1.5"

  local output = stdnse.output_table()
  output.users = {}

  for _, v in ipairs( tbl ) do

    if ( v.oid:match("^" .. h3cUserName) ) then
      local item = {}
      local oldobjid = v.oid:gsub( "^" .. h3cUserName, h3cUserPassword)
      local password = get_value_from_table( tbl, oldobjid )

      if ( password == nil ) or ( #password == 0 ) then
        local newobjid = v.oid:gsub( "^" .. hh3cUserName, hh3cUserPassword)
        password = get_value_from_table( tbl, newobjid )
      end

      oldobjid = v.oid:gsub( "^" .. h3cUserName, h3cUserLevel)
      local level = get_value_from_table( tbl, oldobjid )

      if ( level == nil ) then
        local newobjoid = v.oid:gsub( "^" .. hh3cUserName, hh3cUserLevel)
        level = get_value_from_table( tbl, oldobjid )
      end

      output.users[#output.users + 1] = {username=v.value, password=password, level=level}
    end

  end

  return output
end

action = function(host, port)

  local oldsnmpoid = "1.3.6.1.4.1.2011.10.2.12.1.1.1"
  local newsnmpoid = "1.3.6.1.4.1.25506.2.12.1.1.1"

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  local status, users = snmpHelper:walk( oldsnmpoid )

  if (not(status)) or ( users == nil ) or ( #users == 0 ) then

    -- no status? try new snmp oid
    status, users = snmpHelper:walk( newsnmpoid )

    if (not(status)) or ( users == nil ) or ( #users == 0 ) then
      return nil
    end

  end

  nmap.set_port_state(host, port, "open")
  return process_answer(users)

end

