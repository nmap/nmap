local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local tns = require "tns"
local unpwdb = require "unpwdb"
local rand = require "rand"

local openssl = stdnse.silent_require "openssl"

description = [[
Attempts to enumerate valid Oracle user names against unpatched Oracle 11g
servers (this bug was fixed in Oracle's October 2009 Critical Patch Update).
]]

---
-- @usage
-- nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 <host>
--
-- If no userdb is supplied the default userlist is used
--
-- @output
-- PORT     STATE SERVICE REASON
-- 1521/tcp open  oracle  syn-ack
-- | oracle-enum-users:
-- |   haxxor is a valid user account
-- |   noob is a valid user account
-- |_  patrik is a valid user account
--
-- @args oracle-enum-users.sid the instance against which to attempt user
--       enumeration

-- Version 0.3

-- Created 12/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 21/07/2010 - v0.2 - revised to work with patched systems <patrik>
-- Revised 21/07/2010 - v0.3 - removed references to smb in get_random_string

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}


portrule = shortport.port_or_service(1521, 'oracle-tns' )

local function checkAccount( host, port, user )

  local helper = tns.Helper:new( host, port, nmap.registry.args['oracle-enum-users.sid'] )
  local status, data = helper:Connect()
  local tnscomm, auth
  local auth_options = tns.AuthOptions:new()


  if ( not(status) ) then
    return false, data
  end

  -- A bit ugly, the helper should probably provide a getSocket function
  tnscomm = tns.Comm:new( helper.tnssocket )

  status, auth = tnscomm:exchTNSPacket( tns.Packet.PreAuth:new( user, auth_options, helper.os ) )
  if ( not(status) ) then
    return false, auth
  end
  helper:Close()

  return true, auth["AUTH_VFR_DATA"]
end

local function fail (err) return stdnse.format_output(false, err) end

action = function( host, port )

  local known_good_accounts = { "system", "sys", "dbsnmp", "scott" }

  local status, salt
  local count = 0
  local result = {}
  local usernames

  if ( not( nmap.registry.args['oracle-enum-users.sid'] ) and not( nmap.registry.args['tns.sid'] ) ) then
    return fail("Oracle instance not set (see oracle-enum-users.sid or tns.sid)")
  end

  status, usernames = unpwdb.usernames()
  if( not(status) ) then
    return fail("Failed to load the usernames dictionary")
  end

  -- Check for some known good accounts
  for _, user in ipairs( known_good_accounts ) do
    status, salt = checkAccount(host, port, user)
    if( not(status) ) then return salt  end
    if ( salt ) then
      count = count + #salt
    end
  end

  -- did we atleast get a single salt back?
  if ( count < 20 ) then
    return fail("None of the known accounts were detected (oracle < 11g)")
  end

  -- Check for some known bad accounts
  count = 0
  for i=1, 10 do
    local user = rand.random_string(10,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
    status, salt = checkAccount(host, port, user)
    if( not(status) ) then return salt  end
    if ( salt ) then
      count = count + #salt
    end
  end

  -- It's unlikely that we hit 3 random combinations as valid users
  if ( count > 60 ) then
    return fail(("%d of %d random accounts were detected (Patched Oracle 11G or Oracle 11G R2)"):format(count/20, 10))
  end

  for user in usernames do
    status, salt = checkAccount(host, port, user)
    if ( not(status) ) then return salt end
    if ( salt and #salt == 20 ) then
      table.insert( result, ("%s is a valid user account"):format(user))
    end
  end

  if ( #result == 0 ) then
    table.insert( result, "Failed to find any valid user accounts")
  end

  return stdnse.format_output(true, result)
end
