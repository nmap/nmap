local creds = require "creds"
local redis = require "redis"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"

description = [[
Retrieves information (such as version number and architecture) from a Redis key-value store.
]]

---
-- @usage
-- nmap -p 6379 <ip> --script redis-info
--
-- @output
-- PORT     STATE SERVICE
-- 6379/tcp open  unknown
-- | redis-info:
-- |   Version            2.2.11
-- |   Architecture       64 bits
-- |   Process ID         17821
-- |   Used CPU (sys)     2.37
-- |   Used CPU (user)    1.02
-- |   Connected clients  1
-- |   Connected slaves   0
-- |   Used memory        780.16K
-- |   Role               master
-- |   Bind addresses:
-- |     192.168.121.101
-- |   Active channels:
-- |     testChannel
-- |     bidChannel
-- |   Client connections:
-- |     192.168.171.101
-- |_    72.14.177.105
--
--

author = {"Patrik Karlsson", "Vasiliy Kulikov"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"redis-brute"}


portrule = shortport.port_or_service(6379, "redis")

local function fail(err) return stdnse.format_output(false, err) end

local function cb_parse_version(host, port, val)
  port.version.version = val
  port.version.cpe = port.version.cpe or {}
  table.insert(port.version.cpe, 'cpe:/a:redis:redis:' .. val)
  nmap.set_port_version(host, port)
  return val
end

local function cb_parse_architecture(host, port, val)
  val = ("%s bits"):format(val)
  port.version.extrainfo = val
  nmap.set_port_version(host, port)
  return val
end

local filter = {

  ["redis_version"] = { name = "Version", func = cb_parse_version },
  ["os"] = { name = "Operating System" },
  ["arch_bits"] = { name = "Architecture", func = cb_parse_architecture },
  ["process_id"] = { name = "Process ID"},
  ["uptime"] = { name = "Uptime", func = function(h, p, v) return ("%s seconds"):format(v) end },
  ["used_cpu_sys"]= { name = "Used CPU (sys)"},
  ["used_cpu_user"] = { name = "Used CPU (user)"},
  ["connected_clients"] = { name = "Connected clients"},
  ["connected_slaves"] = { name = "Connected slaves"},
  ["used_memory_human"] = { name = "Used memory"},
  ["role"] = { name = "Role"}

}

local order = {
  "redis_version", "os", "arch_bits", "process_id", "used_cpu_sys",
  "used_cpu_user", "connected_clients", "connected_slaves",
  "used_memory_human", "role"
}

local extras = {
  {
    "Bind addresses", {"CONFIG", "GET", "bind"}, function (data)
      if data[1] ~= "bind" or not data[2] then
        return nil
      end
      local restab = stdnse.strsplit(" ", data[2])
      if not restab or 0 == #restab then
        stdnse.debug1("Failed to parse response from server")
        return nil
      end
      for i, ip in ipairs(restab) do
        if ip == '' then restab[i] = '0.0.0.0' end
      end
      return restab
    end
  },
  {
    "Active channels", {"PUBSUB", "CHANNELS"}, function (data)
      local channels = {}
      local i = 0
      local omitted = 0
      local limit = nmap.verbosity() <= 1 and 20 or false
      for _, channel in ipairs(data) do
        if limit and i > limit then
          omitted = omitted + 1
        else
          table.insert(channels, channel)
        end
        i = i + 1
      end

      if omitted > 0 then
        table.insert(channels, ("(omitted %s item(s), use verbose mode -v to show them)"):format(omitted))
      end
      return i > 0 and channels or nil
    end
  },
  {
    "Client connections", {"CLIENT", "LIST"}, function(data)
      local restab = stdnse.strsplit("\n", data)
      if not restab or 0 == #restab then
        stdnse.debug1("Failed to parse response from server")
        return nil
      end

      local client_ips = {}
      for _, item in ipairs(restab) do
        local ip = item:match("addr=%[?([0-9a-f:.]+)%]?:[0-9]+ ")
        client_ips[ip] = true;
      end
      if not next(client_ips) then
        return nil
      end
      local out = {}
      for ip, _ in pairs(client_ips) do
        local sortable = ipOps.ip_to_str(ip)
        if sortable then
          -- prepending length sorts IPv4 and IPv6 separately
          out[#out+1] = string.pack("s1", sortable)
        end
      end
      if not next(out) then
        return nil
      end
      table.sort(out)
      for i, packed in ipairs(out) do
        out[i] = ipOps.str_to_ip(string.unpack("s1", packed))
      end
      return out
    end
  },
  {
    "Cluster nodes", {"CLUSTER", "NODES"}, function(data)
      local restab = stdnse.strsplit("\n", data)
      if not restab or 0 == #restab then
        return nil
      end

      local ips = {}
      for _, item in ipairs(restab) do
        local id, ip, port, flags = item:match("^([a-f0-9]+) ([0-9.:a-f]+):([0-9]+) ([a-z,]+)")
        stdnse.debug1("ip=%s port=%s flags=%s", ip, port, flags)
        table.insert(ips, ip .. ":" .. port .. " (" .. flags .. ")")
      end

      return ips
    end
  },
}

action = function(host, port)

  local helper = redis.Helper:new(host, port)
  local status = helper:connect()
  if( not(status) ) then
    return fail("Failed to connect to server")
  end

  -- do we have a service password
  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  local cred = c:getCredentials(creds.State.VALID + creds.State.PARAM)()

  if ( cred and cred.pass ) then
    local status, response = helper:reqCmd("AUTH", cred.pass)
    if ( not(status) ) then
      helper:close()
      return fail(response)
    end
  end

  local status, response = helper:reqCmd("INFO")
  if ( not(status) ) then
    helper:close()
    return fail(response)
  end

  if ( redis.Response.Type.ERROR == response.type ) then
    if ( "-ERR operation not permitted" == response.data ) or
        ( "-NOAUTH Authentication required." == response.data ) then
      return fail("Authentication required")
    end
    return fail(response.data)
  end

  local restab = stdnse.strsplit("\r\n", response.data)
  if ( not(restab) or 0 == #restab ) then
    return fail("Failed to parse response from server")
  end

  local kvs = {}
  for _, item in ipairs(restab) do
    local k, v = item:match("^([^:]*):(.*)$")
    if k ~= nil then
      kvs[k] = v
    end
  end

  local result = stdnse.output_table()
  for _, item in ipairs(order) do
    if kvs[item] then
      local name = filter[item].name
      local val

      if filter[item].func then
        val = filter[item].func(host, port, kvs[item])
      else
        val = kvs[item]
      end
      result[name] = val
    end
  end

  for i=1, #extras do
    local name = extras[i][1]
    local cmd = extras[i][2]
    local process = extras[i][3]

    local status, response = helper:reqCmd(table.unpack(cmd))
    if status and redis.Response.Type.ERROR ~= response.type then
      result[name] = process(response.data)
    end
  end
  helper:close()
  return result
end
