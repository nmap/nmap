local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Retrieves information (such as node name and architecture) from a Basho Riak distributed database using the HTTP protocol.
]]

---
-- @usage
-- nmap -p 8098 <ip> --script riak-http-info
--
-- @output
-- PORT     STATE SERVICE
-- 8098/tcp open  http
-- | riak-http-info:
-- |   Node name                  riak@127.0.0.1
-- |   Architecture               x86_64-unknown-linux-gnu
-- |   Storage backend            riak_kv_bitcask_backend
-- |   Total Memory               516550656
-- |   Crypto version             2.0.3
-- |   Skerl version              1.1.0
-- |   OS mon. version            2.2.6
-- |   Basho version              1.0.1
-- |   Lager version              0.9.4
-- |   Cluster info version       1.2.0
-- |   Luke version               0.2.4
-- |   SASL version               2.1.9.4
-- |   System driver version      1.5
-- |   Bitcask version            1.3.0
-- |   Riak search version        1.0.2
-- |   Riak kernel version        2.14.4
-- |   Riak stdlib version        1.17.4
-- |   Basho metrics version      1.0.0
-- |   WebMachine version         1.9.0
-- |   Public key version         0.12
-- |   Riak vore version          1.0.2
-- |   Riak pipe version          1.0.2
-- |   Runtime tools version      1.8.5
-- |   SSL version                4.1.5
-- |   MochiWeb version           1.5.1
-- |   Erlang JavaScript version  1.0.0
-- |   Riak kv version            1.0.2
-- |   Luwak version              1.1.2
-- |   Merge index version        1.0.1
-- |   Inets version              5.6
-- |_  Riak sysmon version        1.0.0
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(8098, "http")

local filter = {
  ["sys_system_architecture"] = { name = "Architecture" },
  ["mem_total"] = { name = "Total Memory" },
  ["crypto_version"] = { name = "Crypto version" },
  ["skerl_version"] = { name = "Skerl version" },
  ["os_mon_version"] = { name = "OS mon. version" },
  ["nodename"] = { name = "Node name" },
  ["basho_stats_version"] = { name = "Basho version" },
  ["lager_version"] = { name = "Lager version" },
  ["cluster_info_version"] = { name = "Cluster info version" },
  ["luke_version"] = { name = "Luke version" },
  ["sasl_version"] = { name = "SASL version" },
  ["sys_driver_version"] = { name = "System driver version" },
  ["bitcask_version"] = { name = "Bitcask version" },
  ["riak_search_version"] = { name = "Riak search version" },
  ["kernel_version"] = { name = "Riak kernel version" },
  ["stdlib_version"] = { name = "Riak stdlib version" },
  ["basho_metrics_version"] = { name = "Basho metrics version" },
  ["webmachine_version"] = { name = "WebMachine version" },
  ["public_key_version"] = { name = "Public key version" },
  ["riak_core_version"] = { name = "Riak vore version" },
  ["riak_pipe_version"] = { name = "Riak pipe version" },
  ["runtime_tools_version"] = { name = "Runtime tools version" },
  ["ssl_version"] = { name = "SSL version" },
  ["mochiweb_version"] = { name = "MochiWeb version"},
  ["erlang_js_version"] = { name = "Erlang JavaScript version" },
  ["riak_kv_version"] = { name = "Riak kv version" },
  ["luwak_version"] = { name = "Luwak version"},
  ["merge_index_version"] = { name = "Merge index version" },
  ["inets_version"] = { name = "Inets version" },
  ["storage_backend"] = { name = "Storage backend" },
  ["riak_sysmon_version"] = { name = "Riak sysmon version" },
}

local order = {
  "nodename", "sys_system_architecture", "storage_backend", "mem_total",
  "crypto_version", "skerl_version", "os_mon_version", "basho_stats_version",
  "lager_version", "cluster_info_version", "luke_version", "sasl_version",
  "sys_driver_version", "bitcask_version", "riak_search_version",
  "kernel_version", "stdlib_version", "basho_metrics_version",
  "webmachine_version", "public_key_version", "riak_core_version",
  "riak_pipe_version", "runtime_tools_version", "ssl_version",
  "mochiweb_version", "erlang_js_version", "riak_kv_version",
  "luwak_version", "merge_index_version", "inets_version", "riak_sysmon_version"
}


local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local response = http.get(host, port, "/stats")

  if ( not(response) or response.status ~= 200 ) then
    return
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- Silently abort if the server responds as anything different than
  -- MochiWeb
  if ( response.header['server'] and
      not(response.header['server']:match("MochiWeb")) ) then
    return
  end

  local status, parsed = json.parse(response.body)
  if ( not(status) ) then
    return fail("Failed to parse response")
  end

  local result = tab.new(2)
  for _, item in ipairs(order) do
    if ( parsed[item] ) then
      local name = filter[item].name
      local val = ( filter[item].func and filter[item].func(parsed[item]) or parsed[item] )
      tab.addrow(result, name, val)
    end
  end
  return stdnse.format_output(true, tab.dump(result))

end
