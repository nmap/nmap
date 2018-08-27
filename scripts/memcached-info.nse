local os = require "os"
local datetime = require "datetime"
local nmap = require "nmap"
local match = require "match"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves information (including system architecture, process ID, and
server time) from distributed memory object caching system memcached.
]]

---
-- @usage
-- nmap -p 11211 --script memcached-info
--
-- @output
-- 11211/udp open  unknown
-- | memcached-info:
-- |   Process ID: 18568
-- |   Uptime: 6950 seconds
-- |   Server time: 2018-03-02T03:35:09
-- |   Architecture: 64 bit
-- |   Used CPU (user): 0.172010
-- |   Used CPU (system): 0.200012
-- |   Current connections: 10
-- |   Total connections: 78
-- |   Maximum connections: 1024
-- |   TCP Port: 11211
-- |   UDP Port: 11211
-- |_  Authentication: no
--
-- @xmloutput
-- <elem key="Process ID">17307</elem>
-- <elem key="Uptime">10662 seconds</elem>
-- <elem key="Server time">2018-03-01T16:46:59</elem>
-- <elem key="Architecture">64 bit</elem>
-- <elem key="Used CPU (user)">0.212809</elem>
-- <elem key="Used CPU (system)">0.157151</elem>
-- <elem key="Current connections">5</elem>
-- <elem key="Total connections">11</elem>
-- <elem key="Maximum connections">1024</elem>
-- <elem key="TCP Port">11211</elem>
-- <elem key="UDP Port">11211</elem>
-- <elem key="Authentication">no</elem>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

local filter = {

  ["pid"] = { name = "Process ID" },
  ["uptime"] = { name = "Uptime", func = function(v) return ("%d seconds"):format(v) end },
  ["time"] = { name = "Server time", func = datetime.format_timestamp },
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

local Comm = {
  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options or {}}
    self.protocol = port.protocol
    self.req_id = math.random(0,0xfff)
    setmetatable(o, self)
    self.__index = self
    return o
  end,
  connect = function(self)
    self.socket = nmap.new_socket(self.protocol)
    self.socket:set_timeout(self.options.timeout or stdnse.get_timeout(self.host))
    return self.socket:connect(self.host, self.port)
  end,
  exchange = function(self, data)
    local req_id = self.req_id
    self.req_id = req_id + 1
    if self.protocol == "udp" then
      data = string.pack(">I2 I2 I2 I2",
        req_id, -- request ID
        0, -- sequence number
        1, -- number of datagrams
        0 -- reserved, must be 0
        ) .. data
    end
    local status = self.socket:send(data)
    if not status then
      return false, "Failed to send request to server"
    end
    if self.protocol == "udp" then
      local msgs = {}
      local dgrams = 0
      repeat
        local status, response = self.socket:receive_bytes(8)
        if not status then return false, "Failed to receive entire response" end
        local resp_id, seq, ndgrams, pos = string.unpack(">I2 I2 I2 xx", response)
        if resp_id == req_id then
          dgrams = ndgrams
          msgs[seq+1] = string.sub(response, pos)
        end
      until #msgs >= dgrams
      return true, table.concat(msgs)
    end

    -- pattern matches ERR or ERROR at the beginning of a string or after a newline
    return self.socket:receive_buf(match.pattern_limit("%f[^\n\0]E[NR][DR]O?R?\r\n", 2048), true)
  end,
}

local function parseResponse(response, expected)
  local kvs = {}
  for k, v in response:gmatch(("%%f[^\n\0]%s ([^%%s]*) (.-)\r\n"):format(expected)) do
    stdnse.debug1("k=%s, v=%s", k, v)
    kvs[k] = v
  end
  return kvs
end

action = function(host, port)

  local client = Comm:new(host, port)
  local status = client:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local request_time = os.time()
  local status, response = client:exchange("stats\r\n")
  if ( not(status) ) then
    return fail(("Failed to send request to server: %s"):format(response))
  end

  local kvs = parseResponse(response, "STAT")
  if kvs.time then
    datetime.record_skew(host, kvs.time, request_time)
  end

  local status, response = client:exchange("stats settings\r\n")
  if ( not(status) ) then
    return fail(("Failed to send request to server: %s"):format(response))
  end

  local kvs2 = parseResponse(response, "STAT")

  kvs = mergetab(kvs, kvs2)

  local result = stdnse.output_table()
  for _, item in ipairs(order) do
    if ( kvs[item] ) then
      local name = filter[item].name
      local val = ( filter[item].func and filter[item].func(kvs[item]) or kvs[item] )
      result[name] = val
    end
  end
  return result

end
