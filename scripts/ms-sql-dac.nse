local mssql = require "mssql"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Queries the Microsoft SQL Browser service for the DAC (Dedicated Admin
Connection) port of a given (or all) SQL Server instance. The DAC port
is used to connect to the database instance when normal connection
attempts fail, for example, when server is hanging, out of memory or
in other bad states. In addition, the DAC port provides an admin with
access to system objects otherwise not accessible over normal
connections.

The DAC feature is accessible on the loopback adapter per default, but
can be activated for remote access by setting the 'remote admin
connection' configuration value to 1. In some cases, when DAC has been
remotely enabled but later disabled, the sql browser service may
incorrectly report it as available. The script therefore attempts to
connect to the reported port in order to verify whether it's
accessible or not.
]]

---
-- @usage
-- sudo nmap -sU -p 1434 --script ms-sql-dac <ip>
--
-- @output
-- | ms-sql-dac:
-- |   SQLSERVER:
-- |     port: 1533
-- |_    state: open
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

dependencies = {"broadcast-ms-sql-discover"}

local function checkPort(host, port)
  local scanport = nmap.get_port_state(host, {number=port, protocol="tcp"})
  if scanport then
    return scanport.state
  end
  local s = nmap.new_socket()
  s:set_timeout(5000)
  local status, err = s:connect(host, port, "tcp")
  s:close()
  return (status and "open" or "closed"), err
end

local function discoverDAC(instance)
  stdnse.debug2("Discovering DAC port on instance: %s", instance:GetName())
  local port = mssql.Helper.DiscoverDACPort(instance)
  if not port then
    return nil
  end

  local result = stdnse.output_table()
  result.port = port
  local state, err = checkPort(instance.host, port)
  result.state = state
  result.error = err
  return result
end

local lib_portrule, lib_hostrule
action, lib_portrule, lib_hostrule = mssql.Helper.InitScript(discoverDAC)

local function rule_if_browser_open(lib_rule)
  return function (host, ...)
    if not lib_rule(host, ...) then
      return false
    end
    local bport = nmap.get_port_state(host, {number=1434, protocol="udp"})
    -- If port is nil, we don't know the state
    return bport == nil or (
      -- we know the state, so it has to be a good one
      bport.state == "open" or bport.state == "open|filtered"
      )
  end
end

portrule = rule_if_browser_open(lib_portrule)
hostrule = rule_if_browser_open(lib_hostrule)
