---
-- This library was written to ease interaction with OpenVAS Manager servers
-- using OMP (OpenVAS Management Protocol) version 2.
--
-- A very small subset of the protocol is implemented.
-- * Connection/authentication
-- * Targets enumeration
--
-- The library can also store accounts in the registry to share them between
-- scripts.
--
-- The complete protocol documentation is available on the official OpenVAS
-- website: http://www.openvas.org/omp-2-0.html
--
-- Sample use:
-- <code>
--    local session = omp2.Session:new()
--    local status, err = session:connect(host, port)
--    local status, err = session:authenticate(username, password)
--    ...
--    session:close()
-- </code>
--
-- @author Henri Doreau
-- @copyright Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- @args omp2.username The username to use for authentication.
-- @args omp2.password The password to use for authentication.
--

local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("omp2", stdnse.seeall)

local HAVE_SSL = false

if pcall(require,'openssl') then
  HAVE_SSL = true
end

--- A Session class holds connection and interaction with the server
Session = {

  --- Creates a new session object
  new = function(self, o)

    o = o or {}
    setmetatable(o, self)
    self.__index = self

    o.username = nmap.registry.args["omp2.username"]
    o.password = nmap.registry.args["omp2.password"]
    o.socket = nmap.new_socket()

    return o
  end,

  --- Establishes the (SSL) connection to the remote server
  connect = function(self, host, port)
    if not HAVE_SSL then
      return false, "The OMP2 module requires OpenSSL support"
    end

    return self.socket:connect(host, port, "ssl")
  end,

  --- Closes connection
  close = function(self)
    return self.socket:close()
  end,

  --- Attempts to authenticate on the current connection
  authenticate = function(self, username, password)
    local status, err, xmldata

    -- TODO escape credentials
    status, err = self.socket:send("<authenticate><credentials>"
      .. "<username>" .. username .. "</username>"
      .. "<password>" .. password .. "</password>"
      .. "</credentials></authenticate>")

    if not status then
      stdnse.debug1("ERROR: %s", err)
      return false, err
    end

    status, xmldata = self.socket:receive()
    if not status then
      stdnse.debug1("ERROR: %s", xmldata)
      return false, xmldata
    end

    return xmldata:match('status="200"')
  end,

  --- Lists targets defined on the remote server
  ls_targets = function(self)
    local status, err, xmldata
    local res, target_names, target_hosts = {}, {}, {}

    status, err = self.socket:send("<get_targets/>")

    if not status then
      stdnse.debug1("ERROR: %s", err)
      return false, err
    end

    status, xmldata = self.socket:receive()
    if not status then
      stdnse.debug1("ERROR: %s", xmldata)
      return false, xmldata
    end

    -- As NSE has no XML parser yet, we use regexp to extract the data from the
    -- XML output. Targets are defined as a name and the corresponding host(s).
    -- Thus we gather both and return an associative array, using names as keys
    -- and hosts as values.

    local i = 0
    for name in xmldata:gmatch("<name>(.-)</name>") do
      -- XXX this is hackish: skip the second and third "<name>" tags, as they
      -- describe other components than the targets.
      -- see: http://www.openvas.org/omp-2-0.html#command_get_targets
      if i % 3 == 0 then
        table.insert(target_names, name)
      end
      i = i + 1
    end

    for hosts in xmldata:gmatch("<hosts>(.-)</hosts>") do
      table.insert(target_hosts, hosts)
    end

    for i, _ in ipairs(target_names) do
      res[target_names[i]] = target_hosts[i]
    end

    return res
  end,
}

--- Registers OMP2 credentials for a given host
function add_account(host, username, password)
  if not nmap.registry[host.ip] then
    nmap.registry[host.ip] = {}
  end

  if not nmap.registry[host.ip]["omp2accounts"] then
    nmap.registry[host.ip]["omp2accounts"] = {}
  end

  table.insert(nmap.registry[host.ip]["omp2accounts"], {["username"] = username, ["password"] = password})
end

--- Retrieves the list of accounts for a given host
function get_accounts(host)
  local accounts = {}
  local username, password

  username = nmap.registry.args["omp2.username"]
  password = nmap.registry.args["omp2.password"]

  if username and password then
    table.insert(accounts, {["username"] = username, ["password"] = password})
  end

  if nmap.registry[host.ip] and nmap.registry[host.ip]["omp2accounts"] then
    for _, account in pairs(nmap.registry[host.ip]["omp2accounts"]) do
      table.insert(accounts, account)
    end
  end

  if #accounts > 0 then
    return accounts
  end
  return nil
end


return _ENV;
