local coroutine = require "coroutine"
local drda = require "drda"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby
]]

---
-- @args drda-brute.threads the amount of accounts to attempt to brute
-- force in parallel (default 10).
-- @args drda-brute.dbname the database name against which to guess
-- passwords (default <code>"SAMPLE"</code>).
--
-- @usage
-- nmap -p 50000 --script drda-brute <target>
--
-- @output
-- 50000/tcp open  drda
-- | drda-brute:
-- |_  db2admin:db2admin => Valid credentials

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories={"intrusive", "brute"}


-- Version 0.5
-- Created 05/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 05/09/2010 - v0.2 - re-wrote as multi-threaded <patrik@cqure.net>
-- Revised 05/10/2010 - v0.3 - revised parallelised design <patrik@cqure.net>
-- Revised 08/14/2010 - v0.4 - renamed script and library from db2* to drda* <patrik@cqure.net>
-- Revised 09/09/2011 - v0.5 - changed account status text to be more consistent with other *-brute scripts

portrule = shortport.port_or_service({50000,60000}, {"drda","ibm-db2"}, "tcp", {"open", "open|filtered"})

--- Credential iterator
--
-- @param usernames iterator from unpwdb
-- @param passwords iterator from unpwdb
-- @return username string
-- @return password string
local function new_usrpwd_iterator (usernames, passwords)
  local function next_username_password ()
    for username in usernames do
      for password in passwords do
        coroutine.yield(username, password)
      end
      passwords("reset")
    end
    while true do coroutine.yield(nil, nil) end
  end
  return coroutine.wrap(next_username_password)
end

--- Iterates over the password list and guesses passwords
--
-- @param host table with information as received by <code>action</code>
-- @param port table with information as received by <code>action</code>
-- @param database string containing the database name
-- @param creds an iterator producing username, password pairs
-- @param valid_accounts table in which to store found accounts
doLogin = function( host, port, database, creds, valid_accounts )
  local helper, status, response, passwords
  local condvar = nmap.condvar( valid_accounts )

  for username, password in creds do
    -- Checks if a password was already discovered for this account
    if ( nmap.registry.db2users == nil or nmap.registry.db2users[username] == nil ) then
      helper = drda.Helper:new()
      helper:connect( host, port )
      stdnse.debug1( "Trying %s/%s against %s...", username, password, host.ip )
      status, response = helper:login( database, username, password )
      helper:close()

      if ( status ) then
        -- Add credentials for future drda scripts to use
        if nmap.registry.db2users == nil then
          nmap.registry.db2users = {}
        end
        nmap.registry.db2users[username]=password
        table.insert( valid_accounts, string.format("%s:%s => Valid credentials", username, password:len()>0 and password or "<empty>" ) )
      end
    end
  end
  condvar("broadcast")
end

--- Checks if the supplied database exists
--
-- @param host table with information as received by <code>action</code>
-- @param port table with information as received by <code>action</code>
-- @param database string containing the database name
-- @return status true on success, false on failure
isValidDb = function( host, port, database )
  local status, response
  local helper = drda.Helper:new()

  helper:connect( host, port )
  -- Authenticate with a static probe account to see if the db is valid
  status, response = helper:login( database, "dbnameprobe1234", "dbnameprobe1234" )
  helper:close()

  if ( not(status) and response:match("Login failed") ) then
    return true
  end
  return false
end

--- Returns the amount of currently active threads
--
-- @param threads table containing the list of threads
-- @return count number containing the number of non-dead threads
threadCount = function( threads )
  local count = 0

  for thread in pairs(threads) do
    if ( coroutine.status(thread) == "dead" ) then
      threads[thread] = nil
    else
      count = count + 1
    end
  end
  return count
end

action = function( host, port )

  local result, response, status = {}, nil, nil
  local valid_accounts, threads = {}, {}
  local usernames, passwords, creds
  local database = stdnse.get_script_args('drda-brute.dbname') or "SAMPLE"
  local condvar = nmap.condvar( valid_accounts )
  local max_threads = tonumber( stdnse.get_script_args('drda-brute.threads') ) or 10

  -- Check if the DB specified is valid
  if( not(isValidDb(host, port, database)) ) then
    return ("The databases %s was not found. (Use --script-args drda-brute.dbname=<dbname> to specify database)"):format(database)
  end

  status, usernames = unpwdb.usernames()
  if ( not(status) ) then
    return "Failed to load usernames"
  end

  -- make sure we have a valid pw file
  status, passwords = unpwdb.passwords()
  if ( not(status) ) then
    return "Failed to load passwords"
  end

  creds = new_usrpwd_iterator( usernames, passwords )

  stdnse.debug1("Starting brute force with %d threads", max_threads )

  for i=1,max_threads do
    local co = stdnse.new_thread( doLogin, host, port, database, creds, valid_accounts )
    threads[co] = true
  end

  -- wait for all threads to finish running
  while threadCount(threads)>0 do
    condvar("wait")
  end

  return stdnse.format_output(true, valid_accounts)

end
