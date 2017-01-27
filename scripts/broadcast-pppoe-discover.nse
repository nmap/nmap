local nmap = require "nmap"
local pppoe = require "pppoe"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Discovers PPPoE (Point-to-Point Protocol over Ethernet) servers using
the PPPoE Discovery protocol (PPPoED).  PPPoE is an ethernet based
protocol so the script has to know what ethernet interface to use for
discovery. If no interface is specified, requests are sent out on all
available interfaces.

As the script send raw ethernet frames it requires Nmap to be run in privileged
mode to operate.
]]

---
-- @usage
-- nmap --script broadcast-pppoe-discover
--
-- @output
-- | broadcast-pppoe-discover:
-- | Server: 08:00:27:AB:CD:EF
-- |   Version: 1
-- |   Type: 1
-- |   TAGs
-- |     AC-Name: ISP
-- |     Service-Name: test
-- |     AC-Cookie: e98010ed8c59a870f0dc94d56ac1095dd321000001
-- |_    Host-Uniq: 7f8552a0

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end
  return true
end

local function fail(err)
  return stdnse.format_output(false, err)
end

local function discoverPPPoE(helper)

  local status, err = helper:connect()
  if ( not(status) ) then
    return false, err
  end

  local status, pado = helper:discoverInit()
  if ( not(status) ) then
    return false, pado
  end

  status, err = helper:discoverRequest()
  if ( not(status) ) then
    return false, err
  end

  return true, pado
end

-- Gets a list of available interfaces based on link and up filters
--
-- @param link string containing the link type to filter
-- @param up string containing the interface status to filter
-- @return result table containing the matching interfaces
local function getInterfaces(link, up)
  if( not(nmap.list_interfaces) ) then return end
  local interfaces, err = nmap.list_interfaces()
  local result
  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
      if ( iface.link == link and iface.up == up ) then
        result = result or {}
        result[iface.device] = true
      end
    end
  end
  return result
end

action = function()

  local interfaces

  -- first check if the user supplied an interface
  if ( nmap.get_interface() ) then
    interfaces = { [nmap.get_interface()] = true }
  else
    interfaces = getInterfaces("ethernet", "up")
  end

  for iface in pairs(interfaces) do
    local helper, err = pppoe.Helper:new(iface)
    if ( not(helper) ) then
      return fail(err)
    end
    local status, pado = discoverPPPoE(helper)
    if ( not(status) ) then
      return fail(pado)
    end
    helper:close()

    local output = { name = ("Server: %s"):format(stdnse.format_mac(pado.mac_srv)) }
    table.insert(output, ("Version: %d"):format(pado.header.version))
    table.insert(output, ("Type: %d"):format(pado.header.type))

    local tags = { name = "TAGs" }
    for _, tag in ipairs(pado.tags) do
      local name, val = pppoe.PPPoE.TagName[tag.tag], tag.decoded
      table.insert(tags, ("%s: %s"):format(name, val))
    end
    table.insert(output, tags)

    return stdnse.format_output(true, output)
  end
end
