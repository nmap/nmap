local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves system information (OS version, available memory, etc.) from
a listening Ganglia Monitoring Daemon or Ganglia Meta Daemon.

Ganglia is a scalable distributed monitoring system for high-performance
computing systems such as clusters and Grids. The information retrieved
includes HDD size, available memory, OS version, architecture (and more) from
each of the systems in each of the clusters in the grid.

For more information about Ganglia, see:
* http://ganglia.sourceforge.net/
* http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Monitoring_Daemon_.28gmond.29
* http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Meta_Daemon_.28gmetad.29
]]

---
-- @usage
-- nmap --script ganglia-info --script-args ganglia-info.timeout=60,ganglia-info.bytes=1000000 -p <port> <target>
--
-- @args ganglia-info.timeout
--       Set the timeout in seconds. The default value is 30.
-- @args ganglia-info.bytes
--       Set the number of bytes to retrieve. The default value is 1000000.
--       This should be enough for a grid of more than 100 hosts.
--       About 5KB-10KB of data is returned for each host in the cluster.
--
-- @output
-- 8649/tcp open   unknown syn-ack
-- | ganglia-info:
-- |   Ganglia Version: 3.1.7
-- |   Cluster 1:
-- |     Name: unspecified
-- |     Owner: unspecified
-- |     Host 1:
-- |       Name: sled9735.sd.dreamhost.com
-- |       IP: 10.208.42.221
-- |       load_one: 0.53
-- |       mem_total: 24685564KB
-- |       os_release: 3.1.9-vs2.3.2.5
-- |       proc_run: 0
-- |       load_five: 0.52
-- |       gexec: OFF
-- |       disk_free: 305.765GB
-- |       mem_cached: 18857264KB
-- |       pkts_in: 821.73packets/sec
-- |       bytes_in: 72686.10bytes/sec
-- |       bytes_out: 5612221.50bytes/sec
-- |       swap_total: 1998844KB
-- |       mem_free: 187964KB
-- |       load_fifteen: 0.57
-- |       os_name: Linux
-- |       boottime: 1429708366s
-- |       cpu_idle: 96.3%
-- |       cpu_user: 2.7%
-- |       cpu_nice: 0.0%
-- |       cpu_aidle: 94.7%
-- |       mem_buffers: 169588KB
-- |       cpu_system: 0.8%
-- |       part_max_used: 31.5%
-- |       disk_total: 435.962GB
-- |       mem_shared: 0KB
-- |       cpu_wio: 0.2%
-- |       machine_type: x86_64
-- |       proc_total: 1027
-- |       cpu_num: 8CPUs
-- |       cpu_speed: 2400MHz
-- |       pkts_out: 3977.13packets/sec
-- |       swap_free: 1393392KB
--
-- @xmloutput
-- <elem key="Ganglia Version">3.1.7</elem>
-- <table key="Cluster 1">
--   <elem key="Name">unspecified</elem>
--   <elem key="Owner">unspecified</elem>
--   <table key="Host 1">
--     <elem key="Name">sled9735.sd.dreamhost.com</elem>
--     <elem key="IP">10.208.42.221</elem>
--     <elem key="load_one">0.53</elem>
--     <elem key="mem_total">24685564KB</elem>
--     <elem key="os_release">3.1.9-vs2.3.2.5</elem>
--     <elem key="proc_run">0</elem>
--     <elem key="load_five">0.52</elem>
--     <elem key="gexec">OFF</elem>
--     <elem key="disk_free">305.765GB</elem>
--     <elem key="mem_cached">18857264KB</elem>
--     <elem key="pkts_in">821.73packets/sec</elem>
--     <elem key="bytes_in">72686.10bytes/sec</elem>
--     <elem key="bytes_out">5612221.50bytes/sec</elem>
--     <elem key="swap_total">1998844KB</elem>
--     <elem key="mem_free">187964KB</elem>
--     <elem key="load_fifteen">0.57</elem>
--     <elem key="os_name">Linux</elem>
--     <elem key="boottime">1429708366s</elem>
--     <elem key="cpu_idle">96.3%</elem>
--     <elem key="cpu_user">2.7%</elem>
--     <elem key="cpu_nice">0.0%</elem>
--     <elem key="cpu_aidle">94.7%</elem>
--     <elem key="mem_buffers">169588KB</elem>
--     <elem key="cpu_system">0.8%</elem>
--     <elem key="part_max_used">31.5%</elem>
--     <elem key="disk_total">435.962GB</elem>
--     <elem key="mem_shared">0KB</elem>
--     <elem key="cpu_wio">0.2%</elem>
--     <elem key="machine_type">x86_64</elem>
--     <elem key="proc_total">1027</elem>
--     <elem key="cpu_num">8CPUs</elem>
--     <elem key="cpu_speed">2400MHz</elem>
--     <elem key="pkts_out">3977.13packets/sec</elem>
--     <elem key="swap_free">1393392KB</elem>
--   </table>
-- </table>
--
-- Version 0.2
-- Created 2011-06-28 - v0.1 - created by Brendan Coles - itsecuritysolutions.org
-- Created 2015-07-30 - v0.2 - Added Support for SLAXML by Gyanendra Mishra

author = {"Brendan Coles", "Gyanendra Mishra"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service ({8649,8651}, "ganglia", {"tcp"})

local function set_name_value(name)
  return function(value, state)
    state.result[name] = value
  end
end

local function set_cluster(name)
  return function(value, state)
    local current = state[#state]
    if not current.out then
      state.cc = state.cc + 1
      current.out = stdnse.output_table()
      current.hc = 0
      state.result["Cluster " .. state.cc] = current.out
    end
    state.result["Cluster " .. state.cc][name] = value
  end
end

local function get_current_cluster(state)
  for i=#state, 1, -1 do
    if state[i][1] == "CLUSTER" then
      return state[i]
    end
  end
end

local function set_host(name)
  return function(value, state)
    local current = state[#state]
    local current_cluster = get_current_cluster(state)
    if not current.out then
      current_cluster.hc = current_cluster.hc + 1
      current.out = stdnse.output_table()
      state.result["Cluster " .. state.cc]["Host " .. current_cluster.hc] = current.out
    end
    state.result["Cluster " .. state.cc]["Host " .. current_cluster.hc][name] = value
  end
end

local function set_metric(name)
  return function(value, state)
    local current = state[#state]
    local current_cluster = get_current_cluster(state)
    current[name] = value
    if current["name"] and current["value"] and current["unit"] then
      state.result["Cluster " .. state.cc]["Host " .. current_cluster.hc][current["name"]] = current["value"] .. current["unit"]
    end
  end
end

local P = {
  GANGLIA_XML = {
    VERSION = set_name_value("Ganglia Version"),
  },
  GRID = {
    NAME = set_name_value("Grid Name"),
  },
  CLUSTER = {
    NAME = set_cluster("Name"),
    OWNER = set_cluster("Owner"),
  },
  HOST = {
    NAME = set_host("Name"),
    IP = set_host("IP"),
  },
  METRIC = {
    NAME = set_metric("name"),
    UNITS = set_metric("unit"),
    VAL  = set_metric("value"),
  }
}

action = function( host, port )

  local result = stdnse.output_table()

  -- Set timeout
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. '.timeout'))
  timeout = timeout or 30

  -- Set bytes
  local bytes = stdnse.get_script_args(SCRIPT_NAME .. '.bytes')
  bytes = tonumber(bytes) or 1000000

  -- Retrieve grid data in XML format over TCP
  stdnse.debug1("Connecting to %s:%s", host.targetname or host.ip, port.number)
  local status, data = comm.get_banner(host, port, {request_timeout=timeout*1000,bytes=bytes})
  if not status then
    stdnse.debug1("Timeout exceeded for %s:%s (Timeout: %ss).", host.targetname or host.ip, port.number, timeout)
    return
  end

  local state = {
    cc = 0,
    result=stdnse.output_table()
  }

  local parser = slaxml.parser:new()
  parser._call = {
    startElement = function(name) table.insert(state, {name}) end,
    closeElement = function(name) assert(state[#state][1] == name) state[#state] = nil end,
    attribute = function(name, value)
      local p_elem = P[state[#state][1]]
      if not (p_elem and p_elem[name]) then return end
      local p_attr = p_elem[name]
      if not p_attr then return end
      p_attr(value, state)
      end,
  }

  parser:parseSAX(data, {stripWhitespace=true})

  if #state.result then return state.result end

end
