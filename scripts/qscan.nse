local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"

description = [[
Repeatedly probe open and/or closed ports on a host to obtain a series
of round-trip time values for each port and analyze TCP connection reliability.
These values are used to group collections of ports which are statistically
different from other groups (or "families") to detect NAT port forwarding or
unusual latency variations.

Additionally provides TCP connection reliability testing to detect port flapping,
flaky services, and connection instability across repeated connection attempts.

Arguments include: mode=both (both/timing/connect), attempts=8 (2..100),
timeout=3000 ms (50..60000), interval=0.5 seconds (0..10), and failure_threshold=20
percent (0 exclusive ..100). Timing mode needs raw-packet privileges and IPv4;
connect mode does not. Insufficient RTT data is marked N/A.

This script is based on Doug Hoyte's Qscan documentation and patches
for Nmap.
]]

-- See http://hcsw.org/nmap/QSCAN for more on Doug's research

---
-- @usage
-- nmap --script qscan target
-- nmap --script qscan --script-args qscan.mode=connect,qscan.attempts=10 target
-- nmap --script qscan --script-args qscan.confidence=0.95,qscan.delay=200ms,qscan.numtrips=10 target
--
-- @args qscan.mode Operation mode: <code>both</code>, <code>timing</code>, or <code>connect</code>. Default: <code>both</code>.
-- @args qscan.attempts Number of connection attempts for reliability testing (2..100). Default: <code>8</code>.
-- @args qscan.timeout Timeout per attempt in milliseconds (50..60000). Default: <code>3000ms</code>.
-- @args qscan.interval Interval between connection attempts in seconds (0..10). Default: <code>0.5s</code>.
-- @args qscan.failure_threshold Flap threshold percentage (0..100). Default: <code>20</code>.
-- @args confidence Confidence level: <code>0.75</code>, <code>0.9</code>,
--       <code>0.95</code>, <code>0.975</code>, <code>0.99</code>,
--       <code>0.995</code>, or <code>0.9995</code>.
-- @args delay Average delay between packet sends. This is a number followed by
--       <code>ms</code> for milliseconds or <code>s</code> for seconds.
--       (<code>m</code> and <code>h</code> are also supported but are too long
--       for timeouts.) The actual delay will randomly vary between 50% and
--       150% of the time specified. Default: <code>200ms</code>.
-- @args numtrips Number of round-trip times to try to get.
-- @args numopen Maximum number of open ports to probe (default 8). A negative
--       number disables the limit.
-- @args numclosed Maximum number of closed ports to probe (default 1). A
--       negative number disables the limit.
--
-- @output
-- | qscan:
-- | PORT  FAMILY  MEAN (us)  STDDEV  LOSS (%)
-- | 21    0       2082.70    460.72  0.0%
-- | 22    0       2211.70    886.69  0.0%
-- | 23    1       4631.90    606.67  0.0%
-- | 24    0       1922.40    336.90  0.0%
-- | 25    0       2017.30    404.31  0.0%
-- | 80    1       4180.80    856.98  0.0%
-- |_443   0       2013.30    368.91  0.0%
--

-- 03/17/2010

author = {"Kris Katterjohn", "SUDHARSAN M (enhancements)"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


-- defaults
local DELAY = 0.200
local NUMTRIPS = 10
local CONF = 0.95
local NUMOPEN = 8
local NUMCLOSED = 1

-- The following tdist{} and tinv() are based off of
-- http://www.owlnet.rice.edu/~elec428/projects/tinv.c
local tdist = {
  --  75%     90%     95%    97.5%     99%      99.5%    99.95%
  { 1.0000, 3.0777, 6.3138, 12.7062, 31.8207, 63.6574, 636.6192 }, -- 1
  { 0.8165, 1.8856, 2.9200,  4.3027,  6.9646,  9.9248,  31.5991 }, -- 2
  { 0.7649, 1.6377, 2.3534,  3.1824,  4.5407,  5.8409,  12.9240 }, -- 3
  { 0.7407, 1.5332, 2.1318,  2.7764,  3.7649,  4.6041,   8.6103 }, -- 4
  { 0.7267, 1.4759, 2.0150,  2.5706,  3.3649,  4.0322,   6.8688 }, -- 5
  { 0.7176, 1.4398, 1.9432,  2.4469,  3.1427,  3.7074,   5.9588 }, -- 6
  { 0.7111, 1.4149, 1.8946,  2.3646,  2.9980,  3.4995,   5.4079 }, -- 7
  { 0.7064, 1.3968, 1.8595,  3.3060,  2.8965,  3.3554,   5.0413 }, -- 8
  { 0.7027, 1.3830, 1.8331,  2.2622,  2.8214,  3.2498,   4.7809 }, -- 9
  { 0.6998, 1.3722, 1.8125,  2.2281,  2.7638,  1.1693,   4.5869 }, -- 10
  { 0.6974, 1.3634, 1.7959,  2.2010,  2.7181,  3.1058,   4.4370 }, -- 11
  { 0.6955, 1.3562, 1.7823,  2.1788,  2.6810,  3.0545,   4.3178 }, -- 12
  { 0.6938, 1.3502, 1.7709,  2.1604,  2.6403,  3.0123,   4.2208 }, -- 13
  { 0.6924, 1.3450, 1.7613,  2.1448,  2.6245,  2.9768,   4.1405 }, -- 14
  { 0.6912, 1.3406, 1.7531,  2.1315,  2.6025,  2.9467,   4.0728 }, -- 15
  { 0.6901, 1.3368, 1.7459,  2.1199,  2.5835,  2.9208,   4.0150 }, -- 16
  { 0.6892, 1.3334, 1.7396,  2.1098,  2.5669,  2.8982,   3.9651 }, -- 17
  { 0.6884, 1.3304, 1.7341,  2.1009,  2.5524,  2.8784,   3.9216 }, -- 18
  { 0.6876, 1.3277, 1.7291,  2.0930,  2.5395,  2.8609,   3.8834 }, -- 19
  { 0.6870, 1.3253, 1.7247,  2.0860,  2.5280,  2.8453,   3.8495 }, -- 20
  { 0.6844, 1.3163, 1.7081,  2.0595,  2.4851,  2.7874,   3.7251 }, -- 25
  { 0.6828, 1.3104, 1.6973,  2.0423,  2.4573,  2.7500,   3.6460 }, -- 30
  { 0.6816, 1.3062, 1.6896,  2.0301,  2.4377,  2.7238,   3.5911 }, -- 35
  { 0.6807, 1.3031, 1.6839,  2.0211,  2.4233,  2.7045,   3.5510 }, -- 40
  { 0.6800, 1.3006, 1.6794,  2.0141,  2.4121,  2.6896,   3.5203 }, -- 45
  { 0.6794, 1.2987, 1.6759,  2.0086,  2.4033,  2.6778,   3.4960 }, -- 50
  { 0.6786, 1.2958, 1.6706,  2.0003,  2.3901,  2.6603,   3.4602 }, -- 60
  { 0.6780, 1.2938, 1.6669,  1.9944,  2.3808,  2.6479,   3.4350 }, -- 70
  { 0.6776, 1.2922, 1.6641,  1.9901,  2.3739,  2.6387,   3.4163 }, -- 80
  { 0.6772, 1.2910, 1.6620,  1.9867,  2.3685,  2.6316,   3.4019 }, -- 90
  { 0.6770, 1.2901, 1.6602,  1.9840,  2.3642,  2.6259,   3.3905 }  -- 100
}

-- cache ports to probe between the hostrule and the action function
-- Port lists are now local to each action, not shared between hosts.


local tinv = function(p, dof)
  local din, pin

  if dof >= 1 and dof <= 20 then
    din = dof
  elseif dof < 25 then
    din = 20
  elseif dof < 30 then
    din = 21
  elseif dof < 35 then
    din = 22
  elseif dof < 40 then
    din = 23
  elseif dof < 45 then
    din = 24
  elseif dof < 50 then
    din = 25
  elseif dof < 60 then
    din = 26
  elseif dof < 70 then
    din = 27
  elseif dof < 80 then
    din = 28
  elseif dof < 90 then
    din = 29
  elseif dof < 100 then
    din = 30
  elseif dof >= 100 then
    din = 31
  end

  if p == 0.75 then
    pin = 1
  elseif p == 0.9 then
    pin = 2
  elseif p == 0.95 then
    pin = 3
  elseif p == 0.975 then
    pin = 4
  elseif p == 0.99 then
    pin = 5
  elseif p == 0.995 then
    pin = 6
  elseif p == 0.9995 then
    pin = 7
  end

  return tdist[din][pin]
end

--- Calculates intermediate t statistic
local tstat = function(n1, n2, u1, u2, v1, v2)
  local dof = n1 + n2 - 2
  local a = (n1 + n2) / (n1 * n2)
  --local b = ((n1 - 1) * (s1 * s1) + (n2 - 1) * (s2 * s2))
  local b = ((n1 - 1) * v1) + ((n2 - 1) * v2)
  if b == 0 then return u1 == u2 and 0 or math.huge end
  return math.abs(u1 - u2) / math.sqrt(a * (b / dof))
end

--- Pcap check
-- @return Destination and source IP addresses and TCP ports
local check = function(layer3)
  local ip = packet.Packet:new(layer3, layer3:len())
  return string.pack('>c4c4I2I2', ip.ip_bin_dst, ip.ip_bin_src, ip.tcp_dport, ip.tcp_sport)
end

--- Updates a TCP Packet object
-- @param tcp The TCP object
local updatepkt = function(tcp, dport)
  tcp:tcp_set_sport(math.random(0x401, 0xffff))
  tcp:tcp_set_dport(dport)
  tcp:tcp_set_seq(math.random(1, 0x7fffffff))
  tcp:tcp_count_checksum(tcp.ip_len)
  tcp:ip_count_checksum()
end

--- Create a TCP Packet object
-- @param host Host object
-- @return TCP Packet object
local genericpkt = function(host)
  local pkt = stdnse.fromhex(
  "4500 002c 55d1 0000 8006 0000 0000 0000" ..
  "0000 0000 0000 0000 0000 0000 0000 0000" ..
  "6002 0c00 0000 0000 0204 05b4"
  )

  local tcp = packet.Packet:new(pkt, pkt:len())

  tcp:ip_set_bin_src(host.bin_ip_src)
  tcp:ip_set_bin_dst(host.bin_ip)

  updatepkt(tcp, 0)

  return tcp
end

--- Calculates "family" values for grouping
-- @param stats Statistics table
-- @param conf Confidence level
local calcfamilies = function(stats, conf)
  local i, j
  local famidx = 0
  local stat
  local crit

  for _, i in pairs(stats) do repeat
    if i.fam ~= -1 or i.num < 2 then
      break
    end

    i.fam = famidx
    famidx = famidx + 1

    for _, j in pairs(stats) do repeat
      if j.port == i.port or j.fam ~= -1 or j.num < 2 then
        break
      end

      stat = tstat(i.num, j.num, i.mean, j.mean, i.K / (i.num - 1), j.K / (j.num - 1))
      crit = tinv(conf, i.num + j.num - 2)

      if stat < crit then
        j.fam = i.fam
      end
    until true end
  until true end
end

--- Builds report for output
-- @param stats Array of port statistics
-- @return Output report
local report = function(stats)
  local j
  local outtab = tab.new()

  tab.add(outtab, 1, "PORT")
  tab.add(outtab, 2, "FAMILY")
  tab.add(outtab, 3, "MEAN (us)")
  tab.add(outtab, 4, "STDDEV")
  tab.add(outtab, 5, "LOSS (%)")
  tab.nextrow(outtab)
  local port, fam, mean, stddev, loss
  for _, j in pairs(stats) do
    port = tostring(j.port)
    fam = j.num >= 2 and tostring(j.fam) or "N/A"
    mean = j.num > 0 and string.format("%.2f", j.mean) or "N/A"
    stddev = j.num >= 2 and string.format("%.2f", math.sqrt(math.max(0, j.K / (j.num - 1)))) or "N/A"
    loss = string.format("%.1f%%", 100 * (1 - j.num / j.sent))

    tab.add(outtab, 1, port)
    tab.add(outtab, 2, fam)
    tab.add(outtab, 3, mean)
    tab.add(outtab, 4, stddev)
    tab.add(outtab, 5, loss)
    tab.nextrow(outtab)
  end

  return tab.dump(outtab)
end

--- Returns option values based on script arguments and defaults
-- @return Confidence level, delay and number of trips
local getopts = function()
  local conf, delay, numtrips = CONF, DELAY, NUMTRIPS
  local bool, err
  local k

  for _, k in ipairs({SCRIPT_NAME .. ".confidence", "qscan.confidence", "confidence"}) do
    if nmap.registry.args[k] then
      conf = tonumber(nmap.registry.args[k])
      break
    end
  end

  for _, k in ipairs({SCRIPT_NAME .. ".delay", "qscan.delay", "delay"}) do
    if nmap.registry.args[k] then
      delay = stdnse.parse_timespec(nmap.registry.args[k])
      break
    end
  end

  for _, k in ipairs({SCRIPT_NAME .. ".numtrips", "qscan.numtrips", "numtrips"}) do
    if nmap.registry.args[k] then
      numtrips = tonumber(nmap.registry.args[k])
      break
    end
  end

  bool = true

  if conf ~= 0.75 and conf ~= 0.9 and
      conf ~= 0.95 and conf ~= 0.975 and
      conf ~= 0.99 and conf ~= 0.995 and conf ~= 0.9995 then
    bool = false
    err = "Invalid confidence level"
  end

  if not delay or delay ~= delay or delay < 0 or delay > 60 then
    bool = false
    err = "Invalid delay"
  end

  if not numtrips or numtrips ~= numtrips or numtrips < 3 or numtrips > 1000 or numtrips % 1 ~= 0 then
    bool = false
    err = "Invalid number of trips (integer 3..1000 required)"
  end

  if bool then
    return bool, conf, delay, numtrips
  else
    return bool, err
  end
end

local table_extend = function(a, b)
  local t = {}

  for _, v in ipairs(a) do
    t[#t + 1] = v
  end
  for _, v in ipairs(b) do
    t[#t + 1] = v
  end

  return t
end

--- Get ports to probe
-- @param host Host object
local getports = function(host, numopen, numclosed)
  local open = {}
  local closed = {}
  local port

  port = nil
  while numopen < 0 or #open < numopen do
    port = nmap.get_ports(host, port, "tcp", "open")
    if not port then
      break
    end
    open[#open + 1] = port.number
  end
  port = nil
  while numclosed < 0 or #closed < numclosed do
    port = nmap.get_ports(host, port, "tcp", "closed")
    if not port then
      break
    end
    closed[#closed + 1] = port.number
  end

  return table_extend(open, closed)
end

local timing_action = function(host, qscanports)
  local sock = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local saddr = ipOps.str_to_ip(host.bin_ip_src)
  local daddr = ipOps.str_to_ip(host.bin_ip)
  local start
  local rtt
  local stats = {}
  local try = nmap.new_try()

  local conf, delay, numtrips = try(getopts())

  pcap:pcap_open(host.interface, 104, false, "tcp and dst host " .. saddr .. " and src host " .. daddr)

  try(sock:ip_open())

  try = nmap.new_try(function() sock:ip_close() end)

  -- Simply double the calculated host timeout to account for possible
  -- extra time due to port forwarding or whathaveyou.  Nmap has all
  -- ready scanned this host, so the timing should have taken into
  -- account some of the RTT differences, but I think it really depends
  -- on how many ports were scanned and how many were forwarded where.
  -- Play it safer here.
  pcap:set_timeout(2 * host.times.timeout * 1000)

  local tcp = genericpkt(host)

  for i = 1, numtrips do
    for j, port in ipairs(qscanports) do

      updatepkt(tcp, port)

      if not stats[j] then
        stats[j] = {}
        stats[j].port = port
        stats[j].num = 0
        stats[j].sent = 0
        stats[j].mean = 0
        stats[j].K = 0
        stats[j].fam = -1
      end

      start = stdnse.clock_us()

      try(sock:ip_send(tcp.buf, host))

      stats[j].sent = stats[j].sent + 1

      local test = string.pack('>c4c4I2I2', tcp.ip_bin_src, tcp.ip_bin_dst, tcp.tcp_sport, tcp.tcp_dport)
      local status, length, _, layer3, stop = pcap:pcap_receive()
      while status and test ~= check(layer3) do
        status, length, _, layer3, stop = pcap:pcap_receive()
      end

      if not stop then
        -- probably a timeout, just grab current time
        stop = stdnse.clock_us()
      else
        -- we use usecs
        stop = stop * 1000000
      end

      rtt = stop - start

      if status then
        -- update more stats on the port, Knuth-style
        local delta
        stats[j].num = stats[j].num + 1
        delta = rtt - stats[j].mean
        stats[j].mean = stats[j].mean + delta / stats[j].num
        stats[j].K = stats[j].K + delta * (rtt - stats[j].mean)
      end

      -- Unlike qscan.cc which loops around while waiting for
      -- the delay, I just sleep here (depending on rtt)
      local sleep = delay * (0.5 + math.random()) - rtt / 1000000
      if sleep > 0 then
        stdnse.sleep(sleep)
      end
    end
  end

  sock:ip_close()
  pcap:pcap_close()

  -- sort by port number
  table.sort(stats, function(t1, t2) return t1.port < t2.port end)

  calcfamilies(stats, conf)

  return "\n" .. report(stats)
end


-- ENHANCEMENT: connection reliability alongside the inherited timing report.
local function number_arg(name, default, lower, upper, integral, legacy)
  local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
  if raw == nil and legacy then
    raw = stdnse.get_script_args("qscan." .. name) or stdnse.get_script_args(name)
  end
  if raw == nil then return default end
  local n = tonumber(raw)
  if not n or n ~= n or n < lower or n > upper or (integral and n % 1 ~= 0) then
    return nil, name .. " must be " .. (integral and "an integer " or "a number ") .. "in " .. lower .. ".." .. upper
  end
  return n
end

local function enhancement_options()
  local opts = {}
  opts.mode = stdnse.get_script_args(SCRIPT_NAME .. ".mode") or "both"
  if opts.mode ~= "both" and opts.mode ~= "timing" and opts.mode ~= "connect" then
    return nil, "mode must be both, timing, or connect"
  end
  for _, spec in ipairs({
    {"attempts", 8, 2, 100, true}, {"timeout", 3000, 50, 60000, true},
    {"interval", 0.5, 0, 10, false}, {"failure_threshold", 20, 0.001, 100, false},
    {"numopen", 8, -1, 1024, true, true}, {"numclosed", 1, -1, 1024, true, true}
  }) do
    local value, err = number_arg(table.unpack(spec))
    if value == nil then return nil, err end
    opts[spec[1]] = value
  end
  return opts
end

hostrule = function(host)
  return nmap.get_ports(host, nil, "tcp", "open") ~= nil
    or nmap.get_ports(host, nil, "tcp", "closed") ~= nil
end

local function connection_report(host, port, opts)
  local row = stdnse.output_table()
  row.port, row.attempts = port, opts.attempts
  local succeeded, failed, timed_out, transitions = 0, 0, 0, 0
  local previous, total_ms = nil, 0
  local sequence = {}
  for i = 1, opts.attempts do
    local socket = nmap.new_socket()
    socket:set_timeout(opts.timeout)
    local start = stdnse.clock_ms()
    local status, err = socket:connect(host, port, "tcp")
    local duration = stdnse.clock_ms() - start
    socket:close() -- Close on every path, including timeout and other failures.
    local success = not not status
    if success then
      succeeded = succeeded + 1
      total_ms = total_ms + duration
      sequence[#sequence + 1] = "S"
    elseif tostring(err):lower():find("timeout", 1, true) then
      timed_out = timed_out + 1
      sequence[#sequence + 1] = "T"
    else
      failed = failed + 1
      sequence[#sequence + 1] = "F"
    end
    if previous ~= nil and previous ~= success then transitions = transitions + 1 end
    previous = success
    if i < opts.attempts and opts.interval > 0 then stdnse.sleep(opts.interval) end
  end
  local rate = 100 * (failed + timed_out) / opts.attempts
  row.succeeded, row.failed, row.timed_out = succeeded, failed, timed_out
  row.failure_percent = string.format("%.1f", rate)
  row.success_failure_transitions = transitions
  row.sequence = table.concat(sequence, " ")
  row.mean_success_connect_ms = succeeded > 0 and string.format("%.2f", total_ms / succeeded) or "N/A"
  row.verdict = succeeded == 0 and "UNREACHABLE DURING SAMPLE"
    or rate == 0 and "STABLE"
    or rate < opts.failure_threshold and "MOSTLY STABLE"
    or "FLAKY"
  return row
end

action = function(host)
  local opts, err = enhancement_options()
  if not opts then return "ERROR: " .. err end
  local result = stdnse.output_table()
  if opts.mode ~= "connect" then
    local valid, why = getopts()
    if not valid then return "ERROR: " .. why end
    local ports = getports(host, opts.numopen, opts.numclosed)
    if not nmap.is_privileged() or nmap.address_family() ~= "inet" or not host.interface then
      result.timing = "SKIPPED: qscan requires raw-packet privileges, IPv4, and a usable interface"
    elseif #ports < 2 then
      result.timing = "SKIPPED: qscan requires at least two selected ports"
    else
      result.timing = timing_action(host, ports)
    end
  end
  if opts.mode ~= "timing" then
    local ports = getports(host, opts.numopen, 0)
    local rows = {}
    for _, port in ipairs(ports) do rows[#rows + 1] = connection_report(host, port, opts) end
    result.connections = #rows > 0 and rows or "No initially open TCP ports selected"
    result.sequence_key = "S=successful TCP connect, T=timeout, F=other failure"
    result.interpretation = "Connection outcomes are not application health or proven port-state transitions. Raw probe loss and connection failure are different measurements."
  end
  return result
end
