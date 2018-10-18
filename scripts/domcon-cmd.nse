local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Runs a console command on the Lotus Domino Console using the given authentication credentials (see also: domcon-brute)
]]

---
-- @usage
-- nmap -p 2050 <host> --script domcon-cmd --script-args domcon-cmd.cmd="show server", \
--   domcon-cmd.user="Patrik Karlsson",domcon-cmd.pass="secret"
--
-- @output
-- PORT     STATE SERVICE REASON
-- 2050/tcp open  unknown syn-ack
-- | domcon-cmd:
-- |   show server
-- |
-- |     Lotus Domino (r) Server (Release 8.5 for Windows/32) 2010-07-30 00:52:58
-- |
-- |     Server name:            server1/cqure - cqure testing server
-- |     Domain name:            cqure
-- |     Server directory:       C:\Program Files\IBM\Lotus\Domino\data
-- |     Partition:              C.Program Files.IBM.Lotus.Domino.data
-- |     Elapsed time:           00:27:11
-- |     Transactions/minute:    Last minute: 0; Last hour: 0; Peak: 0
-- |     Peak # of sessions:     0 at
-- |     Transactions: 0         Max. concurrent: 20
-- |     ThreadPool Threads:     20  (TCPIP Port)
-- |     Availability Index:     100 (state: AVAILABLE)
-- |     Mail Tracking:          Not Enabled
-- |     Mail Journalling:       Not Enabled
-- |     Number of Mailboxes:    1
-- |     Pending mail: 0         Dead mail: 0
-- |     Waiting Tasks:          0
-- |     DAOS:                   Not Enabled
-- |     Transactional Logging:  Not Enabled
-- |     Fault Recovery:         Not Enabled
-- |     Activity Logging:       Not Enabled
-- |     Server Controller:      Enabled
-- |     Diagnostic Directory:   C:\Program Files\IBM\Lotus\Domino\data\IBM_TECHNICAL_SUPPORT
-- |     Console Logging:        Enabled (1K)
-- |     Console Log File:       C:\Program Files\IBM\Lotus\Domino\data\IBM_TECHNICAL_SUPPORT\console.log
-- |_    DB2 Server:             Not Enabled
--
-- @args domcon-cmd.cmd The command to run on the remote server
-- @args domcon-cmd.user The user used to authenticate to the server
-- @args domcon-cmd.pass The password used to authenticate to the server
--

--
-- Version 0.1
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}


portrule = shortport.port_or_service(2050, "dominoconsole", "tcp", "open")

--- Reads an API block from the server
--
-- @param socket already connected to the server
-- @return status true on success, false on failure
-- @return result table containing lines with server response
--         or error message if status is false
local function readAPIBlock( socket )

  local lines
  local result = {}
  local status, line = socket:receive_lines(1)

  if ( not(status) ) then return false, "Failed to read line" end
  lines = stringaux.strsplit( "\n", line )

  for _, line in ipairs( lines ) do
    if ( not(line:match("BeginData")) and not(line:match("EndData")) ) then
      table.insert(result, line)
    end
  end

  -- Clear trailing empty lines
  while( true ) do
    if ( result[#result] == "" ) then
      table.remove(result, #result)
    else
      break
    end
  end

  return true, result

end

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)

  local socket = nmap.new_socket()
  local result_part, result, cmds = {}, {}, {}
  local user = stdnse.get_script_args('domcon-cmd.user')
  local pass = stdnse.get_script_args('domcon-cmd.pass')
  local cmd = stdnse.get_script_args('domcon-cmd.cmd')

  if( not(cmd) ) then return fail("No command supplied (see domcon-cmd.cmd)") end
  if( not(user)) then return fail("No username supplied (see domcon-cmd.user)") end
  if( not(pass)) then return fail("No password supplied (see domcon-cmd.pass)") end

  cmds = stringaux.strsplit(";%s*", cmd)

  socket:set_timeout(10000)
  local status = socket:connect( host, port )
  if ( status ) then
    socket:reconnect_ssl()
  end

  socket:send("#API\n")
  socket:send( ("#UI %s,%s\n"):format(user,pass) )
  socket:receive_lines(1)
  socket:send("#EXIT\n")

  for i=1, #cmds do
    socket:send(cmds[i] .. "\n")
    status, result_part = readAPIBlock( socket )
    if( status ) then
      result_part.name = cmds[i]
      table.insert( result, result_part )
    else
      return fail(result_part)
    end
  end

  socket:close()

  return stdnse.format_output( true, result )
end
