description = [[
Retrieves disk space statistics and information from a remote NFS share.
The output is intended to resemble the output of <code>df</code>.

The script will provide pathconf information of the remote NFS if
the version used is NFSv3.
]]

---
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
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require("stdnse")
require("shortport")
require("rpc")
require("tab")

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

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

  mnt_comm, fhandle = rpc.Helper.MountPath(nfs.host, nfs.port, mount)
  if mnt_comm == nil then
    return false, fhandle
  end

  local nfs_comm, status = rpc.Helper.NfsOpen(nfs.host, nfs.port)
  if nfs_comm == nil then
    rpc.Helper.UnmountPath(mnt_comm, mount)
    return false, status
  end 

  nfs.version = nfs_comm.version

  -- use simple check since NFSv1 is not used anymore.
  if (mnt_comm.version ~= nfs_comm.version) then
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

action = function(host, port)
  local fs_info, mounts, status = {}, {}, {}
  local nfs_info =
  {
    host    = host,
    port    = port,
  }
  nfs_info.human = stdnse.get_script_args('nfs-statfs.human')

  status, mounts = rpc.Helper.ShowMounts( host, port )
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
