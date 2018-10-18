local mssql = require "mssql"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Queries Microsoft SQL Server (ms-sql) instances for a list of databases a user has
access to.

SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
and/or <code>mssql.username</code> & <code>mssql.password</code>)
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

The script needs an account with the sysadmin server role to work.

When run, the script iterates over the credentials and attempts to run
the command for each available set of credentials.

NOTE: The "owner" field in the results will be truncated at 20 characters. This
is a limitation of the <code>sp_MShasdbaccess</code> stored procedure that the
script uses.

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
-- nmap -p 1433 --script ms-sql-hasdbaccess --script-args mssql.username=sa,mssql.password=sa <host>
--
-- @args ms-sql-hasdbaccess.limit limits the amount of databases per-user
--       that are returned (default 5). If set to zero or less all
--       databases the user has access to are returned.
--
-- @output
-- | ms-sql-hasdbaccess:
-- |   [192.168.100.25\MSSQLSERVER]
-- |       webshop_reader
-- |         dbname	owner
-- |         ====== =====
-- |         hr	sa
-- |         finance	sa
-- |         webshop	sa
-- |       lordvader
-- |         dbname	owner
-- |         ====== =====
-- |         testdb	CQURE-NET\Administr
-- |_        webshop	sa

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 - Added ability to run against all instances on a host;
--                 added compatibility with changes in mssql.lua (Chris Woodbury)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "discovery","safe"}


dependencies = {"ms-sql-brute", "ms-sql-empty-password"}


hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()


local function process_instance( instance )

  local status, result, rs
  local query, limit
  local output = {}
  local exclude_dbs = { "'master'", "'tempdb'", "'model'", "'msdb'" }

  local RS_LIMIT = tonumber(stdnse.get_script_args( {'mssql-hasdbaccess.limit', 'ms-sql-hasdbaccess.limit' } )) or 5

  if ( RS_LIMIT <= 0 ) then
    limit = ""
  else
    limit = string.format( "TOP %d", RS_LIMIT )
  end

  local query = { [[CREATE table #hasaccess(dbname varchar(255), owner varchar(255),
    DboOnly bit, ReadOnly bit, SingelUser bit, Detached bit,
    Suspect bit, Offline bit, InLoad bit, EmergencyMode bit,
    StandBy bit, [ShutDown] bit, InRecovery bit, NotRecovered bit )]],


    "INSERT INTO #hasaccess EXEC sp_MShasdbaccess",
    ("SELECT %s dbname, owner FROM #hasaccess WHERE dbname NOT IN(%s)"):format(limit, table.concat(exclude_dbs, ",")),
    "DROP TABLE #hasaccess" }

  local creds = mssql.Helper.GetLoginCredentials_All( instance )
  if ( not creds ) then
    output = "ERROR: No login credentials."
  else
    for username, password in pairs( creds ) do
      local helper = mssql.Helper:new()
      status, result = helper:ConnectEx( instance )
      if ( not(status) ) then
        output = "ERROR: " .. result
        break
      end

      if ( status ) then
        status = helper:Login( username, password, nil, instance.host.ip )
      end

      if ( status ) then
        for _, q in pairs(query) do
          status, result = helper:Query( q )
          if ( status ) then
            -- Only the SELECT statement should produce output
            if ( #result.rows > 0 ) then
              rs = result
            end
          end
        end
      end

      helper:Disconnect()

      if ( status and rs ) then
        result = mssql.Util.FormatOutputTable( rs, true )
        result.name = username
        if ( RS_LIMIT > 0 ) then
          result.name = result.name .. (" (Showing %d first results)"):format(RS_LIMIT)
        end
        table.insert( output, result )
      end
    end
  end


  local instanceOutput = {}
  instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
  table.insert( instanceOutput, output )

  return instanceOutput

end


action = function( host, port )
  local scriptOutput = {}
  local status, instanceList = mssql.Helper.GetTargetInstances( host, port )

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
