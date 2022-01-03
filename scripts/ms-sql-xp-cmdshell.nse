local mssql = require "mssql"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Attempts to run a command using the command shell of Microsoft SQL
Server (ms-sql).

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
the command until either all credentials are exhausted or until the
command is executed.

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
-- nmap -p 445 --script ms-sql-discover,ms-sql-empty-password,ms-sql-xp-cmdshell <host>
-- nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="net user test test /add" <host>
--
-- @args ms-sql-xp-cmdshell.cmd The OS command to run (default: ipconfig /all).
--
-- @output
-- | ms-sql-xp-cmdshell:
-- |   [192.168.56.3\MSSQLSERVER]
-- |     Command: ipconfig /all
-- |       output
-- |       ======
-- |
-- |       Windows IP Configuration
-- |
-- |          Host Name . . . . . . . . . . . . : EDUSRV011
-- |          Primary Dns Suffix  . . . . . . . : cqure.net
-- |          Node Type . . . . . . . . . . . . : Unknown
-- |          IP Routing Enabled. . . . . . . . : No
-- |          WINS Proxy Enabled. . . . . . . . : No
-- |          DNS Suffix Search List. . . . . . : cqure.net
-- |
-- |       Ethernet adapter Local Area Connection 3:
-- |
-- |          Connection-specific DNS Suffix  . :
-- |          Description . . . . . . . . . . . : AMD PCNET Family PCI Ethernet Adapter #2
-- |          Physical Address. . . . . . . . . : 08-00-DE-AD-C0-DE
-- |          DHCP Enabled. . . . . . . . . . . : Yes
-- |          Autoconfiguration Enabled . . . . : Yes
-- |          IP Address. . . . . . . . . . . . : 192.168.56.3
-- |          Subnet Mask . . . . . . . . . . . : 255.255.255.0
-- |          Default Gateway . . . . . . . . . :
-- |          DHCP Server . . . . . . . . . . . : 192.168.56.2
-- |          Lease Obtained. . . . . . . . . . : den 21 mars 2010 00:12:10
-- |          Lease Expires . . . . . . . . . . : den 21 mars 2010 01:12:10
-- |_

-- Created 01/17/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 - Added ability to run against all instances on a host;
--                 added compatibility with changes in mssql.lua (Chris Woodbury)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive"}


dependencies = {"broadcast-ms-sql-discover", "ms-sql-brute", "ms-sql-empty-password"}


local function process_instance( instance )

  local status, result
  local query
  local cmd = stdnse.get_script_args( {'ms-sql-xp-cmdshell.cmd', 'mssql-xp-cmdshell.cmd'} ) or 'ipconfig /all'
  local output = {}

  query = ("EXEC master..xp_cmdshell '%s'"):format(cmd)

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
        status, result = helper:Query( query )
      end
      helper:Disconnect()

      if ( status ) then
        output = mssql.Util.FormatOutputTable( result, true )
        output[ "name" ] = string.format( "Command: %s", cmd )
        break
      elseif ( result and result:gmatch("xp_configure") ) then
        if( nmap.verbosity() > 1 ) then
          output = "Procedure xp_cmdshell disabled. For more information see \"Surface Area Configuration\" in Books Online."
        end
      end
    end
  end

  local instanceOutput = {}
  instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
  table.insert( instanceOutput, output )

  return instanceOutput

end


local do_action
do_action, portrule, hostrule = mssql.Helper.InitScript(process_instance)

action = function(...)
  local scriptOutput = do_action(...)
  if ( not(stdnse.get_script_args( {'ms-sql-xp-cmdshell.cmd', 'mssql-xp-cmdshell.cmd'} ) ) ) then
    table.insert(scriptOutput, 1, "(Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' to change command.)")
  end

  return stdnse.format_output( true, scriptOutput )
end
