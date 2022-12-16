local io = require "io"
local mssql = require "mssql"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Dumps the password hashes from an MS-SQL server in a format suitable for
cracking by tools such as John-the-ripper. In order to do so the user
needs to have the appropriate DB privileges.

Credentials passed as script arguments take precedence over credentials
discovered by other scripts.
]]

---
-- @usage
-- nmap -p 1433 <ip> --script ms-sql-dump-hashes
--
-- @args ms-sql-dump-hashes.dir Dump hashes to a file in this directory. File
--                              name is <ip>_<instance>_ms-sql_hashes.txt.
--                              Default: no file is saved.
--
-- @output
-- PORT     STATE SERVICE
-- 1433/tcp open  ms-sql-s
-- | ms-sql-dump-hashes:
-- |   nmap_test:0x01001234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF0123
-- |   sa:0x01001234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF0123
-- |_  webshop_dbo:0x01001234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF0123

--
--
-- Version 0.1
-- Created 08/03/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "safe"}

dependencies = {"broadcast-ms-sql-discover", "ms-sql-brute", "ms-sql-empty-password"}

local function process_instance(instance)

  local helper = mssql.Helper:new()
  local status, errorMessage = helper:ConnectEx( instance )
  if ( not(status) ) then
    return "ERROR: " .. errorMessage
  end

  status, errorMessage = helper:LoginEx( instance )
  if ( not(status) ) then
    return "ERROR: " .. errorMessage
  end

  local result
  local query = [[
  IF ( OBJECT_ID('master..sysxlogins' ) ) <> 0
    SELECT name, password FROM master..sysxlogins WHERE password IS NOT NULL
  ELSE IF ( OBJECT_ID('master.sys.sql_logins') ) <> 0
    SELECT name, password_hash FROM master.sys.sql_logins
  ]]
  status, result = helper:Query( query )

  local output = {}

  if ( status ) then
    for _, row in ipairs( result.rows ) do
      table.insert(output, ("%s:%s"):format(row[1] or "",row[2] or "") )
    end
  end

  helper:Disconnect()
  return output
end

-- Saves the hashes to file
-- @param filename string name of the file
-- @param response table containing the resultset
-- @return status true on success, false on failure
-- @return err string containing the error if status is false
local function saveToFile(filename, response)
  local f = io.open( filename, "w")
  if ( not(f) ) then
    return false, ("Failed to open file (%s)"):format(filename)
  end
  for _, row in ipairs(response) do
    if ( not(f:write(row .."\n" ) ) ) then
      return false, ("Failed to write file (%s)"):format(filename)
    end
  end
  f:close()
  return true
end

local dir = stdnse.get_script_args("ms-sql-dump-hashes.dir")

local function process_and_save (instance)
  local instanceOutput = process_instance( instance )
  if type(instanceOutput) == "table" then
    local inst = instance:GetName():gsub(".*\\", "")
    local filename = dir .. "/" .. stringaux.filename_escape(
      ("%s_%s_ms-sql_hashes.txt"):format(instance.host.ip, inst))
    saveToFile(filename, instanceOutput)
  end
  return instanceOutput
end

local do_instance = dir and process_and_save or process_instance

action, portrule, hostrule = mssql.Helper.InitScript(do_instance)
