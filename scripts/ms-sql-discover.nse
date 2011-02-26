-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Attempts to discover Microsoft SQL Server instances.

SQL Server credentials required: No (will not benefit from 
<code>mssql.username</code> & <code>mssql.password</code>).
Run criteria:
* Host script: Will always run, unless the <code>mssql.scanned-ports-only</code>
  script argument was specified (see mssql.lua for more details); in that case,
  the script will run if one or more of the following ports were scanned and
  weren't found to be closed: 1434/udp, 1433/tcp, an SMB port (see smb.lua).
* Port script: N/A

The script attempts to discover SQL Server instances. Any instances found are
stored in the Nmap registry for use by any other ms-sql-* scripts that are run
in the same scan.

The script attempts to discover SQL Server instances by the following three
methods:
* Querying the SQL Server Brower service (UDP port 1434): If this service is
available, it will provide detailed information on each of the instances
installed on the host, including an approximate version number (use <code>ms-sql-info</code>
for more accurate and detailed version information). However, this service may
not be running, even if SQL Server instances are present, and it is also possible
for instances to "hide" themselves from the Browser service.
* Connecting to the default SQL Server listening port (TCP port 1433): The script
will attempt to fingerprint the service (if any) listening on TCP port 1433, SQL
Server's default port.
* Connecting via named pipes to the default pipe names: The script will attempt
to connect over SMB to default pipe names for SQL Server.

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
-- nmap -p 445 --script ms-sql-discover <host>
--
-- @output
-- | ms-sql-discover:
-- |   [192.168.100.128\MSSQLSERVER]
-- |     Name: MSSQLSERVER
-- |     Product: Microsoft SQL Server 2000
-- |     TCP port: 1433
-- |     Named pipe: \\192.168.100.128\pipe\sql\query
-- |   [192.168.100.128\SQL2K5]
-- |     Name: SQL2K5
-- |     Product: Microsoft SQL Server 2005
-- |_    Named pipe: \\192.168.100.128\pipe\MSSQL$SQL2K5\sql\query

-- rev 1.0 (2011-02-01) - Initial version (Chris Woodbury)

author = "Chris Woodbury"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require("mssql")
require("smb")

hostrule = function(host)
	local sqlDefaultPort = nmap.get_port_state( host, {number = 1433, protocol = "tcp"} )
	local sqlBrowserPort = nmap.get_port_state( host, {number = 1434, protocol = "udp"} )
	local smbPortNumber = smb.get_port( host )
	
	return (not mssql.SCANNED_PORTS_ONLY) or
			(sqlDefaultPort and sqlDefaultPort.state ~= "closed") or
			(sqlBrowserPort and sqlBrowserPort.state ~= "closed") or
			(smbPortNumber ~= nil)
end


--- Adds a label and value to an output table. If the value is a boolean, it is
--  converted to Yes/No; if the value is nil, nothing is added to the table. 
local function add_to_output_table( outputTable, outputLabel, outputData )

	if outputData ~= nil then
		if outputData == true then
			outputData = "Yes"
		elseif outputData == false then
			outputData = "No"
		end
		
		table.insert(outputTable, string.format( "%s: %s", outputLabel, outputData ) )
	end

end

--- Returns formatted output for the given instance
local function create_instance_output_table( instance )

	local instanceOutput = {}

	instanceOutput["name"] = string.format( "[%s]", instance:GetName() )
	add_to_output_table( instanceOutput, "Name", instance.instanceName )
	if instance.version then add_to_output_table( instanceOutput, "Product", instance.version.productName ) end
	if instance.port then add_to_output_table( instanceOutput, "TCP port", instance.port.number ) end
	add_to_output_table( instanceOutput, "Named pipe", instance.pipeName )

	return instanceOutput

end


action = function(host)
	mssql.Helper.Discover( host )	
	local scriptOutput, instancesFound = {}, nil
	instancesFound = mssql.Helper.GetDiscoveredInstances( host )
	
	if ( instancesFound ) then
		for _, instance in ipairs( instancesFound ) do
	  		local instanceOutput = create_instance_output_table( instance )
			table.insert(scriptOutput, instanceOutput)
	  	end
		stdnse.print_debug( 1, "%s: Found %d instances for %s.", SCRIPT_NAME, #instancesFound, host.ip )
	end
	return stdnse.format_output( true, scriptOutput )
end
