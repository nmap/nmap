local comm = require "comm"
local nmap = require "nmap"
local oops = require "oops"

description = [[
Gets system information from an Idera Uptime Infrastructure Monitor agent.
]]

---
-- @usage
-- nmap --script uptime-agent-info -p 9998 <target>
--
-- @output
-- 9998/tcp open  uptime-agent syn-ack
-- | uptime-agent-info: SYSNAME=system123
-- | DOMAIN=(none)
-- | ARCH="Linux system123 3.12.51-60.20-default #1 SMP Fri Dec 11 12:01:38 UTC 2015 (1ca22d2) x86_64 x86_64 x86_64 GNU/Linux"
-- | OSVER="SUSE Linux Enterprise Server 12 (x86_64)  1 # This file is deprecated and will be removed in a future service pack or release. # Please check /etc/os-release for details about this release. ( 3.12.51-60.20-default x86_64)"
-- | NUMCPUS=2
-- | MEMSIZE=8082576
-- | PAGESIZE=3072
-- | SWAPSIZE=1532924
-- | GPGSLO=0
-- | VXVM=""
-- | SDS=""
-- | LVM="NO"
-- | HOSTID=15ad9120
-- | CPU0=" 0 0 0 2299.998 5 Intel(R)Xeon(R) 0 "
-- | CPU1=" 1 0 0 2299.998 5 Intel(R)Xeon(R) 0 "
-- | NET0=eth0=172.20.16.146
-- | VMWARE=1
-- |_VMUUID=721cce31748ff113b33959b8d14380b9
-- Service Info: Host: system123

author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "default"}

portrule = require "shortport".port_or_service(9998, "uptime-agent")

action = function(host, port)
  -- Ref: https://github.com/uptimesoftware/uptime-openvms-agent/blob/master/uptime-agent.c
  -- Possible commands:
  -- * ver - get up.time version
  -- * sysinfo - lots of info
  -- * df-k - disk usage
  -- * sadc_cpu - unknown, but used as connectivity test in online docs
  -- * mpstat - CPU usage
  -- * netstat - Network interface stats
  -- * tcpinfo - unknown
  -- * psinfo - process info
  -- * whoin - unknown
  -- * sadc_disk - unknown
  -- * rexec - execute a command, requires password. Syntax: rexec pass command args

  local set_port_version = false
  -- Expect about 18 lines, but multiple CPUs can lead to more. Data is sent
  -- line-buffered, so if we guess low, we only get that many lines. Better to
  -- guess high and suffer the timeout.
  local status, info = oops.raise("Error getting system info",
    comm.exchange(host, port, "sysinfo\n", {lines=30}))
  if not status then
    return info
  end

  local hostname = info:match("SYSNAME=([%w_-.]+)")
  if hostname then
    set_port_version = true
    port.version.hostname = hostname
  end

  -- If version detection didn't get it, try to get the up.time version
  if not port.version.version then
    local status, response = comm.exchange(host, port, "ver\n")
    if status then
      local ver = response:match("^up%.time agent ([%d.]+)")
      if ver then
        port.version.name = "uptime-agent"
        port.version.product = "Idera Uptime Infrastructure Monitor"
        port.version.version = ver
        local cpe = port.version.cpe or {}
        cpe[#cpe+1] = ("cpe:/a:idera:uptime_infrastructure_monitor:%s"):format(ver)
        port.version.cpe = cpe
        set_port_version = true
      end
    end
  end

  if set_port_version then
    nmap.set_port_version(host, port, "hardmatched")
  end
  return info
end
