local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Retrieves information (including system architecture, process ID, and
server time) from distributed memory object caching system memcached.
]]

---
-- @usage
-- nmap -p 11211 --script memcached-info
--
-- @output
-- 11211/tcp open  unknown
-- | memcached-info:
-- |   Process ID           18568
-- |   Uptime               6950 seconds
-- |   Server time          Sat Dec 31 14:16:10 2011
-- |   Architecture         64 bit
-- |   Used CPU (user)      0.172010
-- |   Used CPU (system)    0.200012
-- |   Current connections  10
-- |   Total connections    78
-- |   Maximum connections  1024
-- |   TCP Port             11211
-- |   UDP Port             11211
-- |_  Authentication       no
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- currently, we only support the TCP, text based protocol
portrule = shortport.port_or_service(11211, "memcached", "tcp")

local filter = {

  ["pid"] = { name = "Process ID" },
  ["uptime"] = { name = "Uptime", func = function(v) return ("%d seconds"):format(v) end },
  ["time"] = { name = "Server time", func = stdnse.format_timestamp },
  ["pointer_size"] = { name = "Architecture", func = function(v) return v .. " bit" end },
  ["rusage_user"] = { name = "Used CPU (user)" },
  ["rusage_system"] = { name = "Used CPU (system)"},
  ["curr_connections"] = { name = "Current connections"},
  ["total_connections"] = { name = "Total connections"},
  ["maxconns"] = { name = "Maximum connections" },
  ["tcpport"] = { name = "TCP Port" },
  ["udpport"] = { name = "UDP Port" },
  ["auth_enabled_sasl"] = { name = "Authentication" }

}

local order = {
  "pid", "uptime", "time", "pointer_size", "rusage_user", "rusage_system",
  "curr_connections", "total_connections", "maxconns", "tcpport", "udpport",
  "auth_enabled_sasl"
}

local function fail(err) return stdnse.format_output(false, err) end

local function mergetab(tab1, tab2)
  for k, v in pairs(tab2) do
    tab1[k] = v
  end
  return tab1
end

local function recvResponse(socket)
  local kvs = {}
  repeat
    local status, response = socket:receive_buf("\r\n", false)
    if ( not(status) ) then
      return false, "Failed to receive response from server"
    end
    local k,v = response:match("^STAT ([^%s]*) (.*)$")
    if ( k and v ) then
      kvs[k] = v
    end
  until ( "END" == response or "ERROR" == response )

  return true, kvs
end

action = function(host, port)

  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local status = socket:connect(host, port)
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  status = socket:send("stats\r\n")
  if ( not(status) ) then
    return fail("Failed to send request to server")
  end

  local status, kvs = recvResponse(socket)
  if( not(status) ) then
    return fail(kvs)
  end

  status = socket:send("stats settings\r\n")
  if ( not(status) ) then
    return fail("Failed to send request to server")
  end

  local status, kvs2 = recvResponse(socket)
  if( not(status) ) then
    return fail(kvs2)
  end

  kvs = mergetab(kvs, kvs2)

  local result = tab.new(2)
  for _, item in ipairs(order) do
    if ( kvs[item] ) then
      local name = filter[item].name
      local val = ( filter[item].func and filter[item].func(kvs[item]) or kvs[item] )
      tab.addrow(result, name, val)
    end
  end
  return stdnse.format_output(true, tab.dump(result))

end
