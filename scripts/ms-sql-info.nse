local mssql = require "mssql"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Attempts to determine configuration and version information for Microsoft SQL
Server instances.

SQL Server credentials required: No (will not benefit from
<code>mssql.username</code> & <code>mssql.password</code>).
Run criteria:
* Host script: Will always run.
* Port script: N/A

NOTE: Unlike previous versions, this script will NOT attempt to log in to SQL
Server instances. Blank passwords can be checked using the
<code>ms-sql-empty-password</code> script. E.g.:
<code>nmap -sn --script ms-sql-empty-password --script-args mssql.instance-all <host></code>

The script uses two means of getting version information for SQL Server instances:
* Querying the SQL Server Browser service, which runs by default on UDP port
1434 on servers that have SQL Server 2000 or later installed. However, this
service may be disabled without affecting the functionality of the instances.
Additionally, it provides imprecise version information.
* Sending a probe to the instance, causing the instance to respond with
information including the exact version number. This is the same method that
Nmap uses for service versioning; however, this script can also do the same for
instances accessible via Windows named pipes, and can target all of the
instances listed by the SQL Server Browser service.

In the event that the script can connect to the SQL Server Browser service
(UDP 1434) but is unable to connect directly to the instance to obtain more
accurate version information (because ports are blocked or the <code>mssql.scanned-ports-only</code>
argument has been used), the script will rely only upon the version number
provided by the SQL Server Browser/Monitor, which has the following limitations:
* For SQL Server 2000 and SQL Server 7.0 instances, the RTM version number is
always given, regardless of any service packs or patches installed.
* For SQL Server 2005 and later, the version number will reflect the service
pack installed, but the script will not be able to tell whether patches have
been installed.

Where possible, the script will determine major version numbers, service pack
levels and whether patches have been installed. However, in cases where
particular determinations can not be made, the script will report only what can
be confirmed.

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
-- nmap -p 445 --script ms-sql-info <host>
-- nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 <host>
--
-- @output
-- | ms-sql-info:
-- |   Windows server name: WINXP
-- |   192.168.100.128\PROD:
-- |     Instance name: PROD
-- |     Version:
-- |       name: Microsoft SQL Server 2000 SP3
-- |       number: 8.00.760
-- |       Product: Microsoft SQL Server 2000
-- |       Service pack level: SP3
-- |       Post-SP patches applied: No
-- |     TCP port: 1278
-- |     Named pipe: \\192.168.100.128\pipe\MSSQL$PROD\sql\query
-- |     Clustered: No
-- |   192.168.100.128\SQLFIREWALLED:
-- |     Instance name: SQLFIREWALLED
-- |     Version:
-- |       name: Microsoft SQL Server 2008 RTM
-- |       Product: Microsoft SQL Server 2008
-- |       Service pack level: RTM
-- |     TCP port: 4343
-- |     Clustered: No
-- |   \\192.168.100.128\pipe\sql\query:
-- |     Version:
-- |       name: Microsoft SQL Server 2005 SP3+
-- |       number: 9.00.4053
-- |       Product: Microsoft SQL Server 2005
-- |       Service pack level: SP3
-- |       Post-SP patches applied: Yes
-- |_    Named pipe: \\192.168.100.128\pipe\sql\query
--
-- @xmloutput
-- <elem key="Windows server name">WINXP</elem>
-- <table key="192.168.100.128\PROD">
--   <elem key="Instance name">PROD</elem>
--   <table key="Version">
--     <elem key="name">Microsoft SQL Server 2000 SP3</elem>
--     <elem key="number">8.00.760</elem>
--     <elem key="Product">Microsoft SQL Server 2000</elem>
--     <elem key="Service pack level">SP3</elem>
--     <elem key="Post-SP patches applied">No</elem>
--   </table>
--   <elem key="TCP port">1278</elem>
--   <elem key="Named pipe">\\192.168.100.128\pipe\MSSQL$PROD\sql\query</elem>
--   <elem key="Clustered">No</elem>
-- </table>
-- <table key="192.168.100.128\SQLFIREWALLED">
--   <elem key="Instance name">SQLFIREWALLED</elem>
--   <table key="Version">
--     <elem key="name">Microsoft SQL Server 2008 RTM</elem>
--     <elem key="Product">Microsoft SQL Server 2008</elem>
--     <elem key="Service pack level">RTM</elem>
--   </table>
--   <elem key="TCP port">4343</elem>
--   <elem key="Clustered">No</elem>
-- </table>
-- <table key="\\192.168.100.128\pipe\sql\query">
--   <table key="Version">
--     <elem key="name">Microsoft SQL Server 2005 SP3+</elem>
--     <elem key="number">9.00.4053</elem>
--     <elem key="Product">Microsoft SQL Server 2005</elem>
--     <elem key="Service pack level">SP3</elem>
--     <elem key="Post-SP patches applied">Yes</elem>
--   </table>
--   <elem key="Named pipe">\\192.168.100.128\pipe\sql\query</elem>
-- </table>

-- rev 1.0 (2007-06-09)
-- rev 1.1 (2009-12-06 - Added SQL 2008 identification T Sellers)
-- rev 1.2 (2010-10-03 - Added Broadcast support <patrik@cqure.net>)
-- rev 1.3 (2010-10-10 - Added prerule and newtargets support <patrik@cqure.net>)
-- rev 1.4 (2011-01-24 - Revised logic in order to get version data without logging in;
--                       added functionality to interpret version in terms of SP level, etc.
--                       added script arg to prevent script from connecting to ports that
--                         weren't in original Nmap scan <chris3E3@gmail.com>)
-- rev 1.5 (2011-02-01 - Moved discovery functionality into ms-sql-discover.nse and
--               broadcast-ms-sql-discovery.nse <chris3E3@gmail.com>)
-- rev 1.6 (2014-09-04 - Added structured output Daniel Miller)

author = {"Chris Woodbury", "Thomas Buchanan"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

dependencies = {"broadcast-ms-sql-discover"}

--- Returns formatted output for the given version data
local function create_version_output_table( versionInfo )
  local versionOutput = stdnse.output_table()

  versionOutput["name"] = versionInfo:ToString()
  if ( versionInfo.source ~= "SSRP" ) then
    versionOutput["number"] = versionInfo.versionNumber
  end
  versionOutput["Product"] = versionInfo.productName
  versionOutput["Service pack level"] = versionInfo.servicePackLevel
  versionOutput["Post-SP patches applied"] = versionInfo.patched

  return versionOutput
end


--- Returns formatted output for the given instance
local function create_instance_output_table( instance )

  -- if we didn't get anything useful (due to errors or the port not actually
  -- being SQL Server), don't report anything
  if not ( instance.instanceName or instance.version ) then return nil end

  local instanceOutput = stdnse.output_table()

  instanceOutput["Instance name"] = instance.instanceName
  if instance.version then
    instanceOutput["Version"] = create_version_output_table( instance.version )
  end
  if instance.port then instanceOutput["TCP port"] = instance.port.number end
  instanceOutput["Named pipe"] = instance.pipeName
  instanceOutput["Clustered"] = instance.isClustered

  return instanceOutput

end


--- Processes a single instance, attempting to determine its version, etc.
local function process_instance( instance )

  local foundVersion = false
  local ssnetlibVersion

  -- If possible and allowed (see 'mssql.scanned-ports-only' argument), we'll
  -- connect to the instance to get an accurate version number
  if ( instance:HasNetworkProtocols() ) then
    local ssnetlibVersion
    foundVersion, ssnetlibVersion = mssql.Helper.GetInstanceVersion( instance )
    if ( foundVersion ) then
      instance.version = ssnetlibVersion
      stdnse.debug1("Retrieved SSNetLib version for %s.", instance:GetName() )
    else
      stdnse.debug1("Could not retrieve SSNetLib version for %s.", instance:GetName() )
    end
  end

  -- If we didn't get a version from SSNetLib, give the user some detail as to why
  if ( not foundVersion ) then
    if ( not instance:HasNetworkProtocols() ) then
      stdnse.debug1("%s has no network protocols enabled.", instance:GetName() )
    end
    if ( instance.version ) then
      stdnse.debug1("Using version number from SSRP response for %s.", instance:GetName() )
    else
      stdnse.debug1("Version info could not be retrieved for %s.", instance:GetName() )
    end
  end

  -- Give some version info back to Nmap
  if ( instance.port and instance.version ) then
    instance.version:PopulateNmapPortVersion( instance.port )
    nmap.set_port_version( instance.host, instance.port)
  end

end

local function do_instance (instance)
  process_instance( instance )
  return create_instance_output_table( instance )
end

action, portrule, hostrule = mssql.Helper.InitScript(do_instance)
