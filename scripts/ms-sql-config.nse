local mssql = require "mssql"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Queries Microsoft SQL Server (ms-sql) instances for a list of databases, linked servers,
and configuration settings.

SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
and/or <code>mssql.username</code> & <code>mssql.password</code>)
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

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
-- nmap -p 1433 --script ms-sql-config --script-args mssql.username=sa,mssql.password=sa <host>
--
-- @args ms-sql-config.showall If set, shows all configuration options.
--
-- @output
-- | ms-sql-config:
-- |   [192.168.100.25\MSSQLSERVER]
-- |     Databases
-- |       name      db_size owner
-- |       ====      ======= =====
-- |       nmap      2.74 MB MAC-MINI\david
-- |     Configuration
-- |       name      value   inuse   description
-- |       ====      =====   =====   ===========
-- |       SQL Mail XPs      0       0       Enable or disable SQL Mail XPs
-- |       Database Mail XPs 0       0       Enable or disable Database Mail XPs
-- |       SMO and DMO XPs   1       1       Enable or disable SMO and DMO XPs
-- |       Ole Automation Procedures 0       0       Enable or disable Ole Automation Procedures
-- |       xp_cmdshell       0       0       Enable or disable command shell
-- |       Ad Hoc Distributed Queries        0       0       Enable or disable Ad Hoc Distributed Queries
-- |       Replication XPs   0       0       Enable or disable Replication XPs
-- |     Linked Servers
-- |       srvname   srvproduct      providername
-- |       =======   ==========      ============
-- |_      MAC-MINI  SQL Server      SQLOLEDB
--

-- Created 04/02/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 - Added ability to run against all instances on a host;
--                 added compatibility with changes in mssql.lua (Chris Woodbury)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


dependencies = {"ms-sql-brute", "ms-sql-empty-password"}


hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()


--- Processes a set of instances
local function process_instance( instance )

  local status, errorMessage
  local result, result_part = {}, {}
  local conf_filter = stdnse.get_script_args( {'mssql-config.showall', 'ms-sql-config.showall'} ) and ""
    or " WHERE configuration_id > 16384"
  local db_filter = stdnse.get_script_args( {'mssql-config.showall', 'ms-sql-config.showall'} ) and ""
    or " WHERE name NOT IN ('master','model','tempdb','msdb')"
  local helper = mssql.Helper:new()

  local queries = {
    [2]={ ["Configuration"] = [[ SELECT name,
      cast(value as varchar) value,
      cast(value_in_use as varchar) inuse,
      description
      FROM sys.configurations ]] .. conf_filter },
    [3]={ ["Linked Servers"] = [[ SELECT srvname, srvproduct, providername
      FROM master..sysservers
      WHERE srvid > 0 ]] },
    [1]={ ["Databases"] = [[ CREATE TABLE #nmap_dbs(name varchar(255), db_size varchar(255), owner varchar(255),
      dbid int, created datetime, status varchar(512), compatibility_level int )
      INSERT INTO #nmap_dbs EXEC sp_helpdb
      SELECT name, db_size, owner
      FROM #nmap_dbs ]] .. db_filter .. [[
      DROP TABLE #nmap_dbs ]] }
  }

  status, errorMessage = helper:ConnectEx( instance )
  if ( not(status) ) then result = "ERROR: " .. errorMessage end

  if status then
    status, errorMessage = helper:LoginEx( instance )
    if ( not(status) ) then result = "ERROR: " .. errorMessage end
  end

  for _, v in ipairs( queries ) do
    if ( not status ) then break end
    for header, query in pairs(v) do
      status, result_part = helper:Query( query )

      if ( not(status) ) then
        result = "ERROR: " .. result_part
        break
      end
      result_part = mssql.Util.FormatOutputTable( result_part, true )
      result_part.name = header
      table.insert( result, result_part )
    end
  end

  helper:Disconnect()

  local instanceOutput = {}
  instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
  table.insert( instanceOutput, result )

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
