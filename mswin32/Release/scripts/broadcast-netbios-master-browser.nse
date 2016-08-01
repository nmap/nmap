local bit = require "bit"
local netbios = require "netbios"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Attempts to discover master browsers and the domains they manage.
]]

---
-- @usage
-- nmap --script=broadcast-netbios-master-browser
--
-- @output
-- | broadcast-netbios-master-browser:
-- | ip            server        domain
-- |_10.0.200.156  WIN2K3-EPI-1  WORKGROUP
--

-- Version 0.1
-- Created 06/14/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

local function isGroup(flags) return ( bit.band(flags, 0x8000) == 0x8000 ) end

action = function()

  -- NBNS only works over ipv4
  if ( nmap.address_family() == "inet6") then return end

  local MASTER_BROWSER_DOMAIN = 0x1D
  local STD_WORKSTATION_SERVICE = 0x00
  local NBNAME = "\1\2__MSBROWSE__\2\1"
  local BROADCAST_ADDR = "255.255.255.255"

  local status, result = netbios.nbquery( { ip = BROADCAST_ADDR }, NBNAME, { multiple = true })
  if ( not(status) ) then return end

  local outtab = tab.new(3)
  tab.addrow(outtab, 'ip', 'server', 'domain')

  for _, v in ipairs(result) do
    local status, names, _ = netbios.do_nbstat(v.peer)
    local srv_name, domain_name
    if (status) then
      for _, item in ipairs(names) do
        if ( item.suffix == MASTER_BROWSER_DOMAIN and not(isGroup(item.flags)) ) then
          domain_name = item.name
        elseif ( item.suffix == STD_WORKSTATION_SERVICE and not(isGroup(item.flags)) ) then
          srv_name = item.name
        end
      end
      if ( srv_name and domain_name ) then
        tab.addrow(outtab, v.peer, srv_name, domain_name)
      else
        stdnse.debug3("No server name or domain name was found")
      end
    end
  end
  return "\n" .. tab.dump(outtab)
end
