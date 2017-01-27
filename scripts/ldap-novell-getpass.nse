local bin = require "bin"
local comm = require "comm"
local ldap = require "ldap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to retrieve the Novell Universal Password for a user. You
must already have (and include in script arguments) the username and password for an eDirectory server
administrative account.
]]

---
-- Universal Password enables advanced password policies, including extended
-- characters in passwords, synchronization of passwords from eDirectory to
-- other systems, and a single password for all access to eDirectory.
--
-- In case the password policy permits administrators to retrieve user
-- passwords ("Allow admin to retrieve passwords" is set in the password
-- policy) this script can retrieve the password.
--
-- @args ldap-novell-getpass.account The name of the account to retrieve the
--       password for
-- @args ldap-novell-getpass.username The LDAP username to use when connecting
--       to the server
-- @args ldap-novell-getpass.password The LDAP password to use when connecting
--       to the server
--
-- @usage
-- nmap -p 636 --script ldap-novell-getpass --script-args \
-- 'ldap-novell-getpass.username="CN=admin,O=cqure", \
-- ldap-novell-getpass.password=pass1234, \
-- ldap-novell-getpass.account="CN=paka,OU=hr,O=cqure"'
--
-- @output
-- PORT    STATE SERVICE REASON
-- 636/tcp open  ldapssl syn-ack
-- | ldap-novell-getpass:
-- |   Account: CN=patrik,OU=security,O=cqure
-- |_  Password: foobar
--

-- Version 0.1
-- Created 05/11/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service({389,636}, {"ldap","ldapssl"})

local function fail (err) return stdnse.format_output(false, err) end

function action(host,port)

  local username = stdnse.get_script_args("ldap-novell-getpass.username")
  local password = stdnse.get_script_args("ldap-novell-getpass.password") or ""
  local account = stdnse.get_script_args("ldap-novell-getpass.account")

  if ( not(username) ) then
    return fail("No username was supplied (ldap-novell-getpass.username)")
  end
  if ( not(account) ) then
    return fail("No account was supplied (ldap-novell-getpass.account)")
  else
    -- do some basic account validation
    if ( not(account:match("^[Cc][Nn]=.*,") ) ) then
      return fail("The account argument should be specified as: \"CN=name,OU=orgunit,O=org\"")
    end
  end

  -- In order to discover what protocol to use (SSL/TCP) we need to send a
  -- few bytes to the server. An anonymous bind should do it
  local anon_bind = bin.pack("H", "300c020101600702010304008000" )
  local socket, _, opt = comm.tryssl( host, port, anon_bind, nil )
  if ( not(socket) ) then
    return fail("Failed to connect to LDAP server")
  end

  local status, errmsg = ldap.bindRequest( socket, {
    version = 3,
    username = username,
    password = password
  }
  )

  if ( not(status) ) then return errmsg end

  -- Start encoding the NMAS Get Password Request
  local NMASLDAP_GET_PASSWORD_REQUEST = "2.16.840.1.113719.1.39.42.100.13"
  local NMASLDAP_GET_PASSWORD_RESPONSE = "2.16.840.1.113719.1.39.42.100.14"
  -- Add a trailing zero to the account name
  local data = ldap.encode( account .. '\0' )

  -- The following section could do with more documentation
  -- It's based on packet dumps from the getpass utility available from Novell Cool Solutions
  -- encode the account name as a sequence
  data = ldap.encode( { _ldaptype = '30', bin.pack("H", "020101") .. data } )
  data = ldap.encode( { _ldaptype = '81', data } )
  data = ldap.encode( { _ldaptype = '80', NMASLDAP_GET_PASSWORD_REQUEST } ) .. data
  data = ldap.encode( { _ldaptype = '77', data } )

  -- encode the whole extended request as a sequence
  data = ldap.encode( { _ldaptype = '30', bin.pack("H", "020102") .. data } )

  status = socket:send(data)
  if ( not(status) ) then return fail("Failed to send request") end

  status, data = socket:receive()
  if ( not(status) ) then return data end
  socket:close()

  local _, response = ldap.decode(data)

  -- make sure the result code was a success
  local rescode = ( #response >= 2 ) and response[2]
  local respname = ( #response >= 5 ) and response[5]

  if ( rescode ~= 0 ) then
    local errmsg = ( #response >= 4 ) and response[4] or "An unknown error occurred"
    return fail(errmsg)
  end

  -- make sure we get a NMAS Get Password Response back from the server
  if ( respname ~= NMASLDAP_GET_PASSWORD_RESPONSE ) then return end

  local universal_pw = ( #response >= 6 and #response[6] >= 3 ) and response[6][3]

  if ( universal_pw ) then
    local output = {}
    table.insert(output, ("Account: %s"):format(account))
    table.insert(output, ("Password: %s"):format(universal_pw))
    return stdnse.format_output(true, output)
  else
    return fail("No password was found")
  end
end
