local mssql = require "mssql"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

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
instances accessiable via Windows named pipes, and can target all of the
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
-- |   [192.168.100.128\PROD]
-- |     Instance name: PROD
-- |     Version: Microsoft SQL Server 2000 SP3
-- |       Version number: 8.00.760
-- |       Product: Microsoft SQL Server 2005
-- |       Service pack level: SP3
-- |       Post-SP patches applied: No
-- |     TCP port: 1278
-- |     Named pipe: \\192.168.100.128\pipe\MSSQL$PROD\sql\query
-- |     Clustered: No
-- |   [192.168.100.128\SQLFIREWALLED]
-- |     Instance name: SQLFIREWALLED
-- |     Version: Microsoft SQL Server 2008 RTM
-- |       Product: Microsoft SQL Server 2008
-- |       Service pack level: RTM
-- |     TCP port: 4343
-- |     Clustered: No
-- |   [\\192.168.100.128\pipe\sql\query]
-- |     Version: Microsoft SQL Server 2005 SP3+
-- |       Version number: 9.00.4053
-- |       Product: Microsoft SQL Server 2005
-- |       Service pack level: SP3
-- |       Post-SP patches applied: Yes
-- |_    Named pipe: \\192.168.100.128\pipe\sql\query
--

-- rev 1.0 (2007-06-09)
-- rev 1.1 (2009-12-06 - Added SQL 2008 identification T Sellers)
-- rev 1.2 (2010-10-03 - Added Broadcast support <patrik@cqure.net>)
-- rev 1.3 (2010-10-10 - Added prerule and newtargets support <patrik@cqure.net>)
-- rev 1.4 (2011-01-24 - Revised logic in order to get version data without logging in;
--                       added functionality to interpret version in terms of SP level, etc.
--                       added script arg to prevent script from connecting to ports that
--                         weren't in original Nmap scan <chris3E3@gmail.com>)
-- rev 1.5 (2011-02-01 - Moved discovery functionality into ms-sql-discover.nse and
--						   broadcast-ms-sql-discovery.nse <chris3E3@gmail.com>)

author = "Chris Woodbury, Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


hostrule = function(host)
	if ( mssql.Helper.WasDiscoveryPerformed( host ) ) then
		return mssql.Helper.GetDiscoveredInstances( host ) ~= nil
	else
		local sqlDefaultPort = nmap.get_port_state( host, {number = 1433, protocol = "tcp"} )
		local sqlBrowserPort = nmap.get_port_state( host, {number = 1434, protocol = "udp"} )
		-- smb.get_port() will return nil if no SMB port was scanned OR if SMB ports were scanned but none was open
		local smbPortNumber = smb.get_port( host )
		
		if ( (stdnse.get_script_args( {"mssql.instance-all", "mssql.instance-name", "mssql.instance-port"} ) ~= nil) or
				(sqlBrowserPort and (sqlBrowserPort.state == "open" or sqlBrowserPort.state == "open|filtered")) or
				(sqlDefaultPort and (sqlDefaultPort.state == "open" or sqlDefaultPort.state == "open|filtered")) or
				(smbPortNumber ~= nil)  ) then
			return true
		end
	end
end


--- Adds a label and value to an output table. If the value is a boolean, it is
--  converted to Yes/No; if the value is nil, nothing is added to the table. 
local function add_to_output_table( outputTable, outputLabel, outputData )
	if outputData == nil then return end
	
	if outputData == true then
		outputData = "Yes"
	elseif outputData == false then
		outputData = "No"
	end
	
	table.insert(outputTable, string.format( "%s: %s", outputLabel, outputData ) )
end


--- Returns formatted output for the given version data
local function create_version_output_table( versionInfo )
	local versionOutput = {}
	
	versionOutput["name"] = "Version: " .. versionInfo:ToString()
	if ( versionInfo.source ~= "SSRP" ) then
		add_to_output_table( versionOutput, "Version number", versionInfo.versionNumber )
	end
	add_to_output_table( versionOutput, "Product", versionInfo.productName )
	add_to_output_table( versionOutput, "Service pack level", versionInfo.servicePackLevel )
	add_to_output_table( versionOutput, "Post-SP patches applied", versionInfo.patched )
	
	return versionOutput
end


--- Returns formatted output for the given instance
local function create_instance_output_table( instance )

	-- if we didn't get anything useful (due to errors or the port not actually
	-- being SQL Server), don't report anything
	if not ( instance.instanceName or instance.version ) then return nil end

	local instanceOutput = {}
	instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
	
	add_to_output_table( instanceOutput, "Instance name", instance.instanceName )
	if instance.version then
		local versionOutput = create_version_output_table( instance.version )
		table.insert( instanceOutput, versionOutput )
	end
	if instance.port then add_to_output_table( instanceOutput, "TCP port", instance.port.number ) end
	add_to_output_table( instanceOutput, "Named pipe", instance.pipeName )
	add_to_output_table( instanceOutput, "Clustered", instance.isClustered )

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
			stdnse.print_debug( 1, "%s: Retrieved SSNetLib version for %s.", SCRIPT_NAME, instance:GetName() )
		else
			stdnse.print_debug( 1, "%s: Could not retrieve SSNetLib version for %s.", SCRIPT_NAME, instance:GetName() )
		end
	end
	
	-- If we didn't get a version from SSNetLib, give the user some detail as to why
	if ( not foundVersion ) then
		if ( not instance:HasNetworkProtocols() ) then
			stdnse.print_debug( 1, "%s: %s has no network protocols enabled.", SCRIPT_NAME, instance:GetName() )
		end
		if ( instance.version ) then
			stdnse.print_debug( 1, "%s: Using version number from SSRP response for %s.", SCRIPT_NAME, instance:GetName() )
		else
			stdnse.print_debug( 1, "%s: Version info could not be retrieved for %s.", SCRIPT_NAME, instance:GetName() )
		end
	end
	
	-- Give some version info back to Nmap
	if ( instance.port and instance.version ) then
		instance.version:PopulateNmapPortVersion( instance.port )
		nmap.set_port_version( instance.host, instance.port)
	end

end


action = function( host )
	local scriptOutput = {}
	
	local status, instanceList = mssql.Helper.GetTargetInstances( host )
	-- if no instances were targeted, then display info on all
	if ( not status ) then
		if ( not mssql.Helper.WasDiscoveryPerformed( host ) ) then
			mssql.Helper.Discover( host )
		end
		instanceList = mssql.Helper.GetDiscoveredInstances( host )
	end
	
	
	if ( not instanceList ) then
		return stdnse.format_output( false, instanceList or "" )
	else
		for _, instance in ipairs( instanceList ) do
			if instance.serverName then
				table.insert(scriptOutput, string.format( "Windows server name: %s", instance.serverName ))
				break
			end
		end
		for _, instance in pairs( instanceList ) do
			process_instance( instance )
			local instanceOutput = create_instance_output_table( instance )
			if instanceOutput then
				table.insert( scriptOutput, instanceOutput )
			end
		end
	end
	
	return stdnse.format_output( true, scriptOutput )
end

