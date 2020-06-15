local nmap = require "nmap"
local pgsql = require "pgsql"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

local openssl = stdnse.silent_require "openssl"

description = [[
Performs password guessing against PostgreSQL.
]]

---
-- @usage
-- nmap -p 5432 --script pgsql-brute <host>
--
-- @output
-- 5432/tcp open  pgsql
-- | pgsql-brute:
-- |   root:<empty> => Valid credentials
-- |_  test:test => Valid credentials
--
-- @args pgsql.nossl If set to <code>1</code> or <code>true</code>, disables SSL.
-- @args pgsql.version Force protocol version 2 or 3.

-- SSL Encryption
-- --------------
-- We need to handle several cases of SSL support
--  o SSL can be supported on a server level
--  o SSL can be enforced per host or network level
--  o SSL can be denied per host or network level

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- Version 0.4
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/20/2010 - v0.2 - moved version detection to pgsql library
-- Revised 03/04/2010 - v0.3 - added code from ssh-hostkey.nse to check for SSL support
--                           - added support for trusted authentication method
-- Revised 09/10/2011 - v0.4 - changed account status text to be more consistent with other *-brute scripts

portrule = shortport.port_or_service(5432, "postgresql")

--- Connect a socket to the server with or without SSL
--
-- @param host table as received by the action function
-- @param port table as received by the action function
-- @param ssl boolean, if true connect using SSL
-- @return socket connected to server
local function connectSocket(host, port, ssl)
  local socket = nmap.new_socket()

  -- set a reasonable timeout value
  socket:set_timeout(5000)
  socket:connect(host, port)

  -- let's be responsible and avoid sending communication in the clear
  if ( ssl ) then
    local status = pgsql.requestSSL(socket)
    if ( status ) then
      socket:reconnect_ssl()
    end
  end
  return socket
end

action = function( host, port )

  local status, response, ssl_enable, output
  local result, response, status, nossl = {}, nil, nil, false
  local valid_accounts = {}
  local pg

  if ( nmap.registry.args['pgsql.version'] ) then
    if ( tonumber(nmap.registry.args['pgsql.version']) == 2 ) then
      pg = pgsql.v2
    elseif ( tonumber(nmap.registry.args['pgsql.version']) == 3 ) then
      pg = pgsql.v3
    else
      stdnse.debug1("Unsupported version %s", nmap.registry.args['pgsql.version'])
      return
    end
  else
    pg = pgsql.detectVersion(host, port )
  end

  local usernames, passwords
  status, usernames = unpwdb.usernames()
  if not status then
    return stdnse.format_output(false, usernames)
  end

  status, passwords = unpwdb.passwords()
  if not status then
    return stdnse.format_output(false, passwords)
  end

  -- If the user explicitly does not disable SSL, enforce it
  if ( ( nmap.registry.args['pgsql.nossl'] == 'true' ) or
    ( nmap.registry.args['pgsql.nossl'] == '1' ) ) then
    nossl = true
  end

  for username in usernames do
    ssl_enable = not(nossl)
    for password in passwords do
      stdnse.debug1("Trying %s/%s ...", username, password )
      local socket = connectSocket( host, port, ssl_enable )
      status, response = pg.sendStartup(socket, username, username)

      -- if nossl is enforced by the user, we're done
      if ( not(status) and nossl ) then
        break
      end

      -- SSL failed, this can occur due to:
      -- 1. The server does not do SSL
      -- 2. SSL was denied on a per host or network level
      --
      -- Attempt SSL connection
      if ( not(status) ) then
        socket:close()
        ssl_enable = false
        socket = connectSocket( host, port, ssl_enable )
        status, response = pg.sendStartup(socket, username, username)
        if (not(status)) then
          if ( response:match("no pg_hba.conf entry for host") ) then
            stdnse.debug1("The host was denied access to db \"%s\" as user \"%s\", aborting ...", username, username )
            break
          else
            stdnse.debug1("sendStartup returned: %s", response )
            break
          end
        end
      end

      -- Do not attempt to authenticate if authentication type is trusted
      if ( response.authtype ~= pgsql.AuthenticationType.Success ) then
        status, response = pg.loginRequest( socket, response, username, password, response.salt)
      end

      if status then
        -- Add credentials for other pgsql scripts to use
        if nmap.registry.pgsqlusers == nil then
          nmap.registry.pgsqlusers = {}
        end
        nmap.registry.pgsqlusers[username]=password
        if ( response.authtype ~= pgsql.AuthenticationType.Success ) then
          table.insert( valid_accounts, string.format("%s:%s => Valid credentials", username, password:len()>0 and password or "<empty>" ) )
        else
          table.insert( valid_accounts, string.format("%s => Trusted authentication", username ) )
        end
        break
      end
      socket:close()
    end
    passwords("reset")
  end

  output = stdnse.format_output(true, valid_accounts)

  return output

end
