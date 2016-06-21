local creds = require "creds"
local redis = require "redis"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

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
-- |_  Role               master
--

author = "Patrik Karlsson"
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
  helper:close()

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

  local result = tab.new(2)
  for _, item in ipairs(order) do
    if kvs[item] then
      local name = filter[item].name
      local val

      if filter[item].func then
        val = filter[item].func(host, port, kvs[item])
      else
        val = kvs[item]
      end
      tab.addrow(result, name, val)
    end
  end
  return stdnse.format_output(true, tab.dump(result))
end
