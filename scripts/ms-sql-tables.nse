local mssql = require "mssql"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Queries Microsoft SQL Server (ms-sql) for a list of tables per database.

SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
and/or <code>mssql.username</code> & <code>mssql.password</code>)
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

The sysdatabase table should be accessible by more or less everyone.

Once we have a list of databases we iterate over it and attempt to extract
table names. In order for this to succeed we need to have either
sysadmin privileges or an account with access to the db. So, each
database we successfully enumerate tables from we mark as finished, then
iterate over known user accounts until either we have exhausted the users
or found all tables in all the databases.

System databases are excluded.

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
-- nmap -p 1433 --script ms-sql-tables --script-args mssql.username=sa,mssql.password=sa <host>
--
-- @args ms-sql-tables.maxdb Limits the amount of databases that are
--       processed and returned (default 5). If set to zero or less
--       all databases are processed.
--
-- @args ms-sql-tables.maxtables Limits the amount of tables returned
--       (default 5). If set to zero or less all tables are returned.
--
-- @args ms-sql-tables.keywords If set shows only tables or columns matching
--     the keywords
--
-- @output
-- | ms-sql-tables:
-- |   [192.168.100.25\MSSQLSERVER]
-- |   webshop
-- |     table	column	type	length
-- |     payments	user_id	int	4
-- |     payments	purchase_id	int	4
-- |     payments	cardholder	varchar	50
-- |     payments	cardtype	varchar	50
-- |     payments	cardno	varchar	50
-- |     payments	expiry	varchar	50
-- |     payments	cvv	varchar	4
-- |     products	id	int	4
-- |     products	manu	varchar	50
-- |     products	model	varchar	50
-- |     products	productname	varchar	100
-- |     products	price	float	8
-- |     products	imagefile	varchar	255
-- |     products	quantity	int	4
-- |     products	keywords	varchar	100
-- |     products	description	text	16
-- |     users	id	int	4
-- |     users	username	varchar	50
-- |     users	password	varchar	50
-- |_    users	fullname	varchar	100

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 04/02/2010 - v0.2
--    - Added support for filters
--    - Changed output formatting of restrictions
--    - Added parameter information in output if parameters are using their
--      defaults.
-- Revised 02/01/2011 - v0.3 (Chris Woodbury)
--    - Added ability to run against all instances on a host;
--    - Added compatibility with changes in mssql.lua

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


dependencies = {"broadcast-ms-sql-discover", "ms-sql-brute", "ms-sql-empty-password"}

local function process_instance( instance )

  local status, result, dbs, tables

  local output = {}
  local exclude_dbs = { "'master'", "'tempdb'", "'model'", "'msdb'" }
  local db_query
  local done_dbs = {}
  local db_limit, tbl_limit

  local DB_COUNT = tonumber( stdnse.get_script_args( {'ms-sql-tables.maxdb', 'mssql-tables.maxdb'} ) ) or 5
  local TABLE_COUNT = tonumber( stdnse.get_script_args( {'ms-sql-tables.maxtables', 'mssql-tables.maxtables' } ) ) or 2
  local keywords_filter = ""

  if ( DB_COUNT <= 0 ) then
    db_limit = ""
  else
    db_limit = string.format( "TOP %d", DB_COUNT )
  end
  if (TABLE_COUNT <= 0 ) then
    tbl_limit = ""
  else
    tbl_limit = string.format( "TOP %d", TABLE_COUNT )
  end

  local keywords_arg = stdnse.get_script_args( {'ms-sql-tables.keywords', 'mssql-tables.keywords' } )
  -- Build the keyword filter
  if keywords_arg then
    local keywords = keywords_arg
    local tmp_tbl = {}

    if( type(keywords) == 'string' ) then
      keywords = { keywords }
    end

    for _, v in ipairs(keywords) do
      table.insert(tmp_tbl, ("'%s'"):format(v))
    end

    keywords_filter = (" AND ( so.name IN (%s) or sc.name IN (%s) ) "):format(
      table.concat(tmp_tbl, ","),
      table.concat(tmp_tbl, ",")
      )
  end

  db_query = ("SELECT %s name from master..sysdatabases WHERE name NOT IN (%s)"):format(db_limit, table.concat(exclude_dbs, ","))


  local creds = mssql.Helper.GetLoginCredentials_All( instance )
  if ( not creds ) then
    output = "ERROR: No login credentials."
  else
    for username, password in pairs( creds ) do
      local helper = mssql.Helper:new()
      status, result = helper:ConnectEx( instance )
      if ( not(status) ) then
        table.insert(output, "ERROR: " .. result)
        break
      end

      if ( status ) then
        status = helper:Login( username, password, nil, instance.host.ip )
      end

      if ( status ) then
        status, dbs = helper:Query( db_query )
      end

      if ( status ) then
        -- all done?
        if ( #done_dbs == #dbs.rows ) then
          break
        end

        for k, v in pairs(dbs.rows) do
          if ( not( tableaux.contains( done_dbs, v[1] ) ) ) then
            local query = [[ SELECT so.name 'table', sc.name 'column', st.name 'type', sc.length
              FROM %s..syscolumns sc, %s..sysobjects so, %s..systypes st
              WHERE so.id = sc.id AND sc.xtype=st.xtype AND
              so.id IN (SELECT %s id FROM %s..sysobjects WHERE xtype='U') %s ORDER BY so.name, sc.name, st.name]]
            query = query:format( v[1], v[1], v[1], tbl_limit, v[1], keywords_filter)
            status, tables = helper:Query( query )
            if ( not(status) ) then
              stdnse.debug1("%s", tables)
            else
              local item = {}
              item = mssql.Util.FormatOutputTable( tables, true )
              if ( #item == 0 and keywords_filter ~= "" ) then
                table.insert(item, "Filter returned no matches")
              end
              item.name = v[1]

              table.insert(output, item)
              table.insert(done_dbs, v[1])
            end
          end
        end
      end
      helper:Disconnect()
    end

    local pos = 1
    local restrict_tbl = {}

    if keywords_arg then
      local tmp = keywords_arg
      if ( type(tmp) == 'table' ) then
        tmp = table.concat(tmp, ',')
      end
      table.insert(restrict_tbl, 1, ("Filter: %s"):format(tmp))
      pos = pos + 1
    else
      table.insert(restrict_tbl, 1, "No filter (see ms-sql-tables.keywords)")
    end

    if ( DB_COUNT > 0 ) then
      local tmp = ("Output restricted to %d databases"):format(DB_COUNT)
      if ( not(stdnse.get_script_args( { 'ms-sql-tables.maxdb', 'mssql-tables.maxdb' } ) ) ) then
        tmp = tmp .. " (see ms-sql-tables.maxdb)"
      end
      table.insert(restrict_tbl, 1, tmp)
      pos = pos + 1
    end

    if ( TABLE_COUNT > 0 ) then
      local tmp = ("Output restricted to %d tables"):format(TABLE_COUNT)
      if ( not(stdnse.get_script_args( { 'ms-sql-tables.maxtables', 'mssql-tables.maxtables' } ) ) ) then
        tmp = tmp .. " (see ms-sql-tables.maxtables)"
      end
      table.insert(restrict_tbl, 1, tmp)
      pos = pos + 1
    end

    if ( 1 < pos and type( output ) == "table" and #output > 0) then
      restrict_tbl.name = "Restrictions"
      table.insert(output, "")
      table.insert(output, restrict_tbl)
    end
  end


  local instanceOutput = {}
  instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
  table.insert( instanceOutput, output )

  return stdnse.format_ouptut(true, instanceOutput)

end


action, portrule, hostrule = mssql.Helper.InitScript(process_instance)
