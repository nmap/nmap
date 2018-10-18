local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Shows NFS exports, like the <code>showmount -e</code> command.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-showmount:
-- |   /home/storage/backup 10.46.200.0/255.255.255.0
-- |_  /home 1.2.3.4/255.255.255.255 10.46.200.0/255.255.255.0
--

-- Version 0.7

-- Created 11/23/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 11/24/2009 - v0.2 - added RPC query to find mountd ports
-- Revised 11/24/2009 - v0.3 - added a hostrule instead of portrule
-- Revised 11/26/2009 - v0.4 - reduced packet sizes and documented them
-- Revised 01/24/2009 - v0.5 - complete rewrite, moved all NFS related code into nselib/nfs.lua
-- Revised 02/22/2009 - v0.6 - adapted to support new RPC library
-- Revised 03/13/2010 - v0.7 - converted host to port rule


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"rpc-grind"}


portrule = shortport.port_or_service(111, {"rpcbind", "mountd"}, {"tcp", "udp"} )

local function get_exports(host, port)
  local mnt = rpc.Mount:new()
  local mountver
  if host.registry.nfs then
    mountver = host.registry.nfs.mountver
  else
    host.registry.nfs = {}
  end
  if mountver == nil then
    local low, high = string.match(port.version.version, "(%d)%-(%d)")
    if high == nil then
      mountver = tonumber(port.version.version)
    else
      mountver = tonumber(high)
    end
  end
  local mnt_comm = rpc.Comm:new('mountd', mountver)
  local status, result = mnt_comm:Connect(host, port)
  if ( not(status) ) then
    stdnse.debug4("get_exports: %s", result)
    return false, result
  end
  host.registry.nfs.mountver = mountver
  host.registry.nfs.mountport = port
  local status, mounts = mnt:Export(mnt_comm)
  mnt_comm:Disconnect()
  if ( not(status) ) then
    stdnse.debug4("get_exports: %s", mounts)
  end
  return status, mounts
end

action = function(host, port)

    local status, mounts, proto
    local result = {}

    if port.service == "mountd" then
      status, mounts = get_exports( host, port )
    else
      status, mounts = rpc.Helper.ShowMounts( host, port )
    end

    if not status or mounts == nil then
        return stdnse.format_output(false, mounts)
    end

    if #mounts < 1 then
      return "No NFS mounts available"
    end

    for _, v in ipairs( mounts ) do
        local entry = v.name .. " " .. table.concat(v, " ")
        table.insert( result, entry )
    end

    return stdnse.format_output( true, result )

end
