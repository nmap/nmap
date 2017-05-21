local mssql = require "mssql"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Discovers Microsoft SQL servers in the same broadcast domain.

SQL Server credentials required: No (will not benefit from
<code>mssql.username</code> & <code>mssql.password</code>).

The script attempts to discover SQL Server instances in the same broadcast
domain. Any instances found are stored in the Nmap registry for use by any
other ms-sql-* scripts that are run in the same scan.

In contrast to the <code>ms-sql-discover</code> script, the broadcast version
will use a broadcast method rather than targeting individual hosts. However, the
broadcast version will only use the SQL Server Browser service discovery method.
]]

---
-- @usage
-- nmap --script broadcast-ms-sql-discover
-- nmap --script broadcast-ms-sql-discover,ms-sql-info --script-args=newtargets
--
-- @output
-- | broadcast-ms-sql-discover:
-- |   192.168.100.128 (WINXP)
-- |     [192.168.100.128\MSSQLSERVER]
-- |       Name: MSSQLSERVER
-- |       Product: Microsoft SQL Server 2000
-- |       TCP port: 1433
-- |       Named pipe: \\192.168.100.128\pipe\sql\query
-- |     [192.168.100.128\SQL2K5]
-- |       Name: SQL2K5
-- |       Product: Microsoft SQL Server 2005
-- |       Named pipe: \\192.168.100.128\pipe\MSSQL$SQL2K5\sql\query
-- |   192.168.100.150 (SQLSRV)
-- |     [192.168.100.150\PROD]
-- |       Name: PROD
-- |       Product: Microsoft SQL Server 2008
-- |_      Named pipe: \\192.168.100.128\pipe\sql\query
--

-- Created 07/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/01/2011 - v0.2 - Added compatibility with changes in mssql.lua (Chris Woodbury)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end


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

action = function()

  local host = { ip = "255.255.255.255" }
  local port = { number = 1434, protocol = "udp" }

  local status, result = mssql.Helper.DiscoverBySsrp(host, port, true)
  if ( not(status) ) then return end

  local scriptOutput = {}
  for ip, instanceList in pairs(result) do
    local serverOutput, serverName = {}, nil
    target.add( ip )
    for _, instance in ipairs( instanceList ) do
      serverName = serverName or instance.serverName
      local instanceOutput = create_instance_output_table( instance )
      table.insert(serverOutput, instanceOutput)
    end
    serverOutput.name = string.format( "%s (%s)", ip, serverName )
    table.insert( scriptOutput, serverOutput )
  end

  return stdnse.format_output( true, scriptOutput )

end
