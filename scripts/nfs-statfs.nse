local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local nmap = require "nmap"

description = [[
Retrieves disk space statistics and information from a remote NFS share.
The output is intended to resemble the output of <code>df</code>.

The script will provide pathconf information of the remote NFS if
the version used is NFSv3.
]]

---
-- @usage
-- nmap -p 111 --script=nfs-statfs <target>
-- nmap -sV --script=nfs-statfs <target>
-- @output
-- PORT    STATE SERVICE
-- | nfs-statfs:
-- |   Filesystem           1K-blocks  Used     Available  Use%  Blocksize
-- |   /mnt/nfs/files       5542276    2732012  2528728    52%   4096
-- |_  /mnt/nfs/opensource  5534416    620640   4632644    12%   4096
--
-- @args nfs-statfs.human If set to <code>1</code> or <code>true</code>,
--       shows file sizes in a human readable format with suffixes like
--       <code>KB</code> and <code>MB</code>.

-- Version 0.3

-- Created 01/25/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/22/2010 - v0.2 - adapted to support new RPC library
-- Revised 03/13/2010 - v0.3 - converted host to port rule
-- Revised 06/28/2010 - v0.4 - added NFSv3 support and doc


author = "Patrik Karlsson, Djalal Harouni"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"rpc-grind"}


portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

hostrule = function(host)
  local mountport, nfsport
  if host.registry.nfs then
    mountport = host.registry.nfs.mountport
    nfsport = host.registry.nfs.nfsport
  else
    host.registry.nfs = {}
  end
  for _,proto in ipairs({"tcp","udp"}) do
    local port = nmap.get_ports(host, nil, proto, "open")
    while port do
      if port.version then
        if port.service == "mountd" then
          mountport = port
        elseif port.service == "nfs" then
          nfsport = port
        end
      end
      if mountport and nfsport then break end
      port = nmap.get_ports(host, port, proto, "open")
    end
    if mountport and nfsport then break end
  end
  if nfsport == nil then return false end
  if host.registry.nfs.nfsver == nil then
    local low, high = string.match(nfsport.version.version, "(%d)%-(%d)")
    if high == nil then
      high = tonumber(nfsport.version.version)
      if high == 4 then
        return false --Can't support version 4
      else
        host.registry.nfs.nfsver = high
      end
    else
      if high == "4" then
        host.registry.nfs.nfsver = 3
      else
        host.registry.nfs.nfsver = tonumber(low)
      end
    end
  end
  if mountport == nil then return false end
  if host.registry.nfs.mountver == nil then
    local low, high = string.match(mountport.version.version, "(%d)%-(%d)")
    if high == nil then
      host.registry.nfs.mountver = tonumber(mountport.version.version)
    else
      host.registry.nfs.mountver = tonumber(high)
    end
  end
  host.registry.nfs.mountport = mountport
  host.registry.nfs.nfsport = nfsport
  return (mountport and nfsport)
end

local procedures = { }

local function table_fsstat(nfs, mount, stats)
  local fs, err = rpc.Util.calc_fsstat_table(stats, nfs.version, nfs.human)
  if fs == nil then
    return false, err
  end
  fs.filesystem = string.format("%s", mount)
  return true, fs
end

local function table_fsinfo(nfs, fsinfo)
  local ret = {}
  local fs, err = rpc.Util.calc_fsinfo_table(fsinfo, nfs.version, nfs.human)
  if fs == nil then
    return false, err
  end

  ret.maxfilesize = fs.maxfilesize
  return true, ret
end

local function table_pathconf(nfs, pconf)
  local ret = {}
  local fs, err = rpc.Util.calc_pathconf_table(pconf, nfs.version)
  if fs == nil then
    return false, err
  end

  ret.linkmax = fs.linkmax
  return true, ret
end

local function report(nfs, tables)
  local outtab, tab_size, tab_avail
  local tab_filesys, tab_used, tab_use,
        tab_bs, tab_maxfs, tab_linkmax = "Filesystem",
        "Used", "Use%", "Blocksize", "Maxfilesize", "Maxlink"

  if nfs.human then
    tab_size = "Size"
    tab_avail = "Avail"
  else
    tab_size = "1K-blocks"
    tab_avail = "Available"
  end

  if nfs.version == 2 then
    outtab = tab.new()
    tab.addrow(outtab, tab_filesys, tab_size, tab_used,
                       tab_avail, tab_use, tab_bs)
    for _, t in ipairs(tables) do
      tab.addrow(outtab, t.filesystem, t.size,
                         t.used, t.available, t.use, t.bsize)
    end
  elseif nfs.version == 3 then
    outtab = tab.new()
    tab.addrow(outtab, tab_filesys, tab_size, tab_used,
                       tab_avail, tab_use, tab_maxfs, tab_linkmax)
    for _, t in ipairs(tables) do
      tab.addrow(outtab, t.filesystem, t.size, t.used,
                        t.available, t.use, t.maxfilesize, t.linkmax)
    end
  end

  return tab.dump(outtab)
end

local function nfs_filesystem_info(nfs, mount, filesystem)
  local results, res, status = {}, {}
  local nfsobj = rpc.NFS:new()
  local mnt_comm, nfs_comm, fhandle

  mnt_comm, fhandle = procedures.MountPath(nfs.host, mount)
  if mnt_comm == nil then
    return false, fhandle
  end

  local nfs_comm, status = procedures.NfsOpen(nfs.host)
  if nfs_comm == nil then
    rpc.Helper.UnmountPath(mnt_comm, mount)
    return false, status
  end

  nfs.version = nfs_comm.version

  -- use simple check since NFSv1 is not used anymore, and NFSv4 not supported
  if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
    rpc.Helper.UnmountPath(mnt_comm, mount)
    return false, string.format("versions mismatch, nfs v%d - mount v%d",
                                nfs_comm.version, mnt_comm.version)
  end

  if nfs_comm.version < 3 then
    status, res = nfsobj:StatFs(nfs_comm, fhandle)
  elseif nfs_comm.version == 3 then
    status, res = nfsobj:FsStat(nfs_comm, fhandle)
  end

  if status then
    status, res = table_fsstat(nfs, mount, res)
    if status then
      for k, v in pairs(res) do
        results[k] = v
      end
    end

    if nfs_comm.version == 3 then
      status, res = nfsobj:FsInfo(nfs_comm, fhandle)
      if status then
        status, res = table_fsinfo(nfs, res)
        if status then
          for k, v in pairs(res) do
            results[k] = v
          end
        end
      end

      status, res = nfsobj:PathConf(nfs_comm, fhandle)
      if status then
        status, res = table_pathconf(nfs, res)
        if status then
          for k, v in pairs(res) do
            results[k] = v
          end
        end
      end

    end
  end

  rpc.Helper.NfsClose(nfs_comm)
  rpc.Helper.UnmountPath(mnt_comm, mount)
  if (not(status)) then
    return status, res
  end

  table.insert(filesystem, results)
  return true, nil
end

mainaction = function(host)
  local fs_info, mounts, status = {}, {}, {}
  local nfs_info =
  {
    host    = host,
  }
  nfs_info.human = stdnse.get_script_args('nfs-statfs.human')

  status, mounts = procedures.ShowMounts( host )
  if (not(status)) then
    return stdnse.format_output(false, mounts)
  end

  for _, v in ipairs(mounts) do
    local err
    status, err = nfs_filesystem_info(nfs_info, v.name, fs_info)
    if (not(status)) then
      return stdnse.format_output(false,
                  string.format("%s: %s", v.name, err))
    end
  end

  return stdnse.format_output(true, report(nfs_info, fs_info))
end

hostaction = function(host)
  procedures = {
    ShowMounts = function(ahost)
      local mnt_comm, status, result, mounts
      local mnt = rpc.Mount:new()
      mnt_comm = rpc.Comm:new('mountd', host.registry.nfs.mountver)
      status, result = mnt_comm:Connect(ahost, host.registry.nfs.mountport)
      if ( not(status) ) then
        stdnse.debug4("ShowMounts: %s", result)
        return false, result
      end
      status, mounts = mnt:Export(mnt_comm)
      mnt_comm:Disconnect()
      if ( not(status) ) then
        stdnse.debug4("ShowMounts: %s", mounts)
      end
      return status, mounts
    end,

    MountPath = function(ahost, path)
      local fhandle, status, err
      local mountd, mnt_comm
      local mnt = rpc.Mount:new()

      mnt_comm = rpc.Comm:new("mountd", host.registry.nfs.mountver)

      status, err = mnt_comm:Connect(host, host.registry.nfs.mountport)
      if not status then
        stdnse.debug4("MountPath: %s", err)
        return nil, err
      end

      status, fhandle = mnt:Mount(mnt_comm, path)
      if not status then
        mnt_comm:Disconnect()
        stdnse.debug4("MountPath: %s", fhandle)
        return nil, fhandle
      end

      return mnt_comm, fhandle
    end,

    NfsOpen = function(ahost)
      local nfs_comm, status, err

      nfs_comm = rpc.Comm:new('nfs', host.registry.nfs.nfsver)
      status, err = nfs_comm:Connect(host, host.registry.nfs.nfsport)
      if not status then
        stdnse.debug4("NfsOpen: %s", err)
        return nil, err
      end

      return nfs_comm, nil
    end,
  }
  return mainaction(host)
end

portaction = function(host, port)
  procedures = {
    ShowMounts = function(ahost)
      return rpc.Helper.ShowMounts(ahost, port)
    end,
    MountPath = function(ahost, path)
      return rpc.Helper.MountPath(ahost, port, path)
    end,
    NfsOpen = function(ahost)
      return rpc.Helper.NfsOpen(ahost, port)
    end,
  }
  return mainaction(host)
end

local ActionsTable = {
  -- portrule: use rpcbind service
  portrule = portaction,
  -- hostrule: Talk to services directly
  hostrule = hostaction
}

action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
