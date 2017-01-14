local creds = require "creds"
local nmap = require "nmap"
local rpcap = require "rpcap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to the rpcap service (provides remote sniffing capabilities
through WinPcap) and retrieves interface information. The service can either be
setup to require authentication or not and also supports IP restrictions.
]]

---
-- @usage
-- nmap -p 2002 <ip> --script rpcap-info
-- nmap -p 2002 <ip> --script rpcap-info --script-args="creds.rpcap='administrator:foobar'"
--
-- @output
-- PORT     STATE SERVICE REASON
-- 2002/tcp open  rpcap   syn-ack
-- | rpcap-info:
-- |   \Device\NPF_{0D5D1364-1F1F-4892-8AC3-B838258F9BB8}
-- |     Intel(R) PRO/1000 MT Desktop Adapter
-- |     Addresses
-- |         fe80:0:0:0:aabb:ccdd:eeff:0011
-- |         192.168.1.127/24
-- |   \Device\NPF_{D5EAD105-B0BA-4D38-ACB4-6E95512BC228}
-- |     Hamachi Virtual Network Interface Driver
-- |     Addresses
-- |_        fe80:0:0:0:aabb:ccdd:eeff:0022
--
-- @args creds.rpcap username:password to use for authentication
--
-- @see rpcap-brute.nse

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"rpcap-brute"}


portrule = shortport.port_or_service(2002, "rpcap", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

local function getInfo(host, port, username, password)

  local helper = rpcap.Helper:new(host, port)
  local status, resp = helper:connect()
  if ( not(status) ) then
    return false, "Failed to connect to server"
  end
  status, resp = helper:login(username, password)

  if ( not(status) ) then
    return false, resp
  end

  status, resp = helper:findAllInterfaces()
  helper:close()
  if ( not(status) ) then
    return false, resp
  end

  port.version.name = "rpcap"
  port.version.product = "WinPcap remote packet capture daemon"
  nmap.set_port_version(host, port)

  return true, resp
end

action = function(host, port)

  -- patch-up the service name, so creds.rpcap will work, ugly but needed as
  -- tcp 2002 is registered to the globe service in nmap-services ...
  port.service = "rpcap"

  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  local states = creds.State.VALID + creds.State.PARAM
  local status, resp = getInfo(host, port)

  if ( status ) then
    return stdnse.format_output(true, resp)
  end

  for cred in c:getCredentials(states) do
    status, resp = getInfo(host, port, cred.user, cred.pass)
    if ( status ) then
      return stdnse.format_output(true, resp)
    end
  end

  return fail(resp)
end
