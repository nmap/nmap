local mssql = require "mssql"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Performs password guessing against Microsoft SQL Server (ms-sql). Works best in
conjunction with the <code>broadcast-ms-sql-discover</code> script.

SQL Server credentials required: No  (will not benefit from <code>mssql.username</code> & <code>mssql.password</code>).

Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code> or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code> and <code>mssql.instance-port</code> script arguments are NOT used.

WARNING: SQL Server 2005 and later versions include support for account lockout
policies (which are enforced on a per-user basis). If an account is locked out,
the script will stop running for that instance, unless the
<code>ms-sql-brute.ignore-lockout</code> argument is used.

NOTE: Communication with instances via named pipes depends on the <code>smb</code>
library. To communicate with (and possibly to discover) instances via named pipes,
the host must have at least one SMB port (e.g. TCP 445) that was scanned and
found to be open. Additionally, named pipe connections may require Windows
authentication to connect to the Windows host (via SMB) in addition to the
authentication required to connect to the SQL Server instances itself. See the
documentation and arguments for the <code>smb</code> library for more information.

NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
with ports that were not included in the port list for the Nmap scan. This can
be disabled using the <code>mssql.scanned-ports-only</code> script argument.
]]

---
-- @usage
-- nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt <host>
-- nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt <host>
--
-- @output
-- | ms-sql-brute:
-- |   [192.168.100.128\TEST]
-- |     No credentials found
-- |     Warnings:
-- |       sa: AccountLockedOut
-- |   [192.168.100.128\PROD]
-- |     Credentials found:
-- |       webshop_reader:secret => Login Success
-- |       testuser:secret1234 => PasswordMustChange
-- |_      lordvader:secret1234 => Login Success
--
----
-- @args ms-sql-brute.ignore-lockout WARNING! Including this argument will cause
--      the script to continue attempting to brute-forcing passwords for users
--      even after a user has been locked out. This may result in many SQL
--      Server logins being locked out!
--
-- @args ms-sql-brute.brute-windows-accounts  Enable targeting Windows accounts
--          as part of the brute force attack.  This should be used in conjunction
--          with the mssql library's mssql.domain argument.
--

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 (Chris Woodbury)
--    - Added ability to run against all instances on a host;
--    - Added recognition of account-locked out and password-expired error codes;
--    - Added storage of credentials on a per-instance basis
--    - Added compatibility with changes in mssql.lua

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}

dependencies = {"ms-sql-empty-password"}



hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()


--- Returns formatted output for the given instance
local function create_instance_output_table( instance )

  local instanceOutput = {}
  instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
  if ( instance.ms_sql_brute.credentials ) then
    local credsOutput = {}
    credsOutput["name"] = "Credentials found:"
    table.insert( instanceOutput, credsOutput )

    for username, result in pairs( instance.ms_sql_brute.credentials ) do
      local password = result[1]
      local errorCode = result[2]
      password = password:len()>0 and password or "<empty>"
      if errorCode then
        local errorMessage = mssql.LoginErrorMessage[ errorCode ] or "unknown error"
        table.insert( credsOutput, string.format( "%s:%s => %s", username, password, errorMessage ) )
      else
        table.insert( credsOutput, string.format( "%s:%s => Login Success", username, password ) )
      end
    end

    if ( #credsOutput == 0 ) then
      table.insert( instanceOutput, "No credentials found" )
    end
  end

  if ( instance.ms_sql_brute.warnings ) then
    local warningsOutput = {}
    warningsOutput["name"] = "Warnings:"
    table.insert( instanceOutput, warningsOutput )

    for _, warning in ipairs( instance.ms_sql_brute.warnings ) do
      table.insert( warningsOutput, warning )
    end
  end

  if ( instance.ms_sql_brute.errors ) then
    local errorsOutput = {}
    errorsOutput["name"] = "Errors:"
    table.insert( instanceOutput, errorsOutput )

    for _, error in ipairs( instance.ms_sql_brute.errors ) do
      table.insert( errorsOutput, error )
    end
  end

  return instanceOutput

end


local function test_credentials( instance, helper, username, password )
  local database = "tempdb"
  local stopUser, stopInstance = false, false

  local status, result = helper:ConnectEx( instance )
  local loginErrorCode
  if( status ) then
    stdnse.debug2("Attempting login to %s as %s/%s", instance:GetName(), username, password )
    status, result, loginErrorCode = helper:Login( username, password, database, instance.host.ip )
  end
  helper:Disconnect()

  local passwordIsGood, canLogin
  if status then
    passwordIsGood = true
    canLogin = true
  elseif ( loginErrorCode ) then
    if ( ( loginErrorCode ~= mssql.LoginErrorType.InvalidUsernameOrPassword ) and
        ( loginErrorCode ~= mssql.LoginErrorType.NotAssociatedWithTrustedConnection ) ) then
      stopUser = true
    end

    if ( loginErrorCode == mssql.LoginErrorType.PasswordExpired ) then passwordIsGood = true
    elseif ( loginErrorCode == mssql.LoginErrorType.PasswordMustChange ) then passwordIsGood = true
    elseif ( loginErrorCode == mssql.LoginErrorType.AccountLockedOut ) then
      stdnse.debug1("Account %s locked out on %s", username, instance:GetName() )
      table.insert( instance.ms_sql_brute.warnings, string.format( "%s: Account is locked out.", username ) )
      if ( not stdnse.get_script_args( "ms-sql-brute.ignore-lockout" ) ) then
        stopInstance = true
      end
    end
    if ( mssql.LoginErrorMessage[ loginErrorCode ] == nil ) then
      stdnse.debug2("%s: Attemping login to %s as (%s/%s): Unknown login error number: %s",
        SCRIPT_NAME, instance:GetName(), username, password, loginErrorCode )
      table.insert( instance.ms_sql_brute.warnings, string.format( "Unknown login error number: %s", loginErrorCode ) )
    end
    stdnse.debug3("%s: Attempt to login to %s as (%s/%s): %d (%s)",
      SCRIPT_NAME, instance:GetName(), username, password, loginErrorCode, tostring( mssql.LoginErrorMessage[ loginErrorCode ] ) )
  else
    table.insert( instance.ms_sql_brute.errors, string.format("Network error. Skipping instance. Error: %s", result ) )
    stopUser = true
    stopInstance = true
  end

  if ( passwordIsGood ) then
    stopUser = true

    instance.ms_sql_brute.credentials[ username ] = { password, loginErrorCode }
    -- Add credentials for other ms-sql scripts to use but don't
    -- add accounts that need to change passwords
    if ( canLogin ) then
      instance.credentials[ username ] = password
      -- Legacy storage method (does not distinguish between instances)
      nmap.registry.mssqlusers = nmap.registry.mssqlusers or {}
      nmap.registry.mssqlusers[username]=password
    end
  end

  return stopUser, stopInstance
end

--- Processes a single instance, attempting to detect an empty password for "sa"
local function process_instance( instance )

  -- One of this script's features is that it will report an instance's
  -- in both the port-script results and the host-script results. In order to
  -- avoid redundant login attempts on an instance, we will just make the
  -- attempt once and then re-use the results. We'll use a mutex to make sure
  -- that multiple script instances (e.g. a host-script and a port-script)
  -- working on the same SQL Server instance can only enter this block one at
  -- a time.
  local mutex = nmap.mutex( instance )
  mutex( "lock" )

  -- If this instance has already been tested (e.g. if we got to it by both the
  -- hostrule and the portrule), don't test it again.
  if ( instance.tested_brute ~= true ) then
    instance.tested_brute = true

    instance.credentials = instance.credentials or {}
    instance.ms_sql_brute = instance.ms_sql_brute or {}
    instance.ms_sql_brute.credentials = instance.ms_sql_brute.credentials or {}
    instance.ms_sql_brute.warnings = instance.ms_sql_brute.warnings or {}
    instance.ms_sql_brute.errors = instance.ms_sql_brute.errors or {}

    local result, status
    local stopUser, stopInstance
    local usernames, passwords, username, password
    local helper = mssql.Helper:new()

    if ( not instance:HasNetworkProtocols() ) then
      stdnse.debug1("%s has no network protocols enabled.", instance:GetName() )
      table.insert( instance.ms_sql_brute.errors, "No network protocols enabled." )
      stopInstance = true
    end

    status, usernames = unpwdb.usernames()
    if ( not(status) ) then
      stdnse.debug1("Failed to load usernames list." )
      table.insert( instance.ms_sql_brute.errors, "Failed to load usernames list." )
      stopInstance = true
    end

    if ( status ) then
      status, passwords = unpwdb.passwords()
      if ( not(status) ) then
        stdnse.debug1("Failed to load passwords list." )
        table.insert( instance.ms_sql_brute.errors, "Failed to load passwords list." )
        stopInstance = true
      end
    end

    if ( status ) then
      for username in usernames do
        if stopInstance then break end

        -- See if the password is the same as the username (which may not
        -- be in the password list)
        stopUser, stopInstance = test_credentials( instance, helper, username, username )

        for password in passwords do
          if stopUser then break end

          stopUser, stopInstance = test_credentials( instance, helper, username, password )
        end

        passwords("reset")
      end
    end
  end

  -- The password testing has been finished. Unlock the mutex.
  mutex( "done" )

  return create_instance_output_table( instance )

end


action = function( host, port )
  local scriptOutput = {}
  local status, instanceList = mssql.Helper.GetTargetInstances( host, port )

  local domain, bruteWindows = stdnse.get_script_args("mssql.domain", "ms-sql-brute.brute-windows-accounts")

  if ( domain and not(bruteWindows) ) then
    local ret = "\n  " ..
    "Windows authentication was enabled but the argument\n  " ..
    "ms-sql-brute.brute-windows-accounts was not given. As there is currently no\n  " ..
    "way of detecting accounts being locked out when Windows authentication is \n  " ..
    "used, make sure that the amount entries in the password list\n  " ..
    "(passdb argument) are at least 2 entries below the lockout threshold."
    return ret
  end

  if ( not status ) then
    return stdnse.format_output( false, instanceList )
  else
    for _, instance in pairs( instanceList ) do
      local instanceOutput = process_instance( instance )
      if instanceOutput then
        table.insert( scriptOutput, instanceOutput )
      end
    end
  end

  return stdnse.format_output( true, scriptOutput )
end
