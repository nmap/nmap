local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local nmap = require "nmap"

description = [[
Attempts to get useful information about files from NFS exports.
The output is intended to resemble the output of <code>ls</code>.

The script starts by enumerating and mounting the remote NFS exports. After 
that it performs an NFS GETATTR procedure call for each mounted point
in order to get its ACLs.
For each mounted directory the script will try to list its file entries
with their attributes.

Since the file attributes shown in the results are the result of
GETATTR, READDIRPLUS, and similar procedures, the attributes
are the attributes of the local filesystem.

These access permissions are shown only with NFSv3:
* Read:     Read data from file or read a directory.
* Lookup:   Look up a name in a directory
            (no meaning for non-directory objects).
* Modify:   Rewrite existing file data or modify existing
            directory entries.
* Extend:   Write new data or add directory entries.
* Delete:   Delete an existing directory entry.
* Execute:  Execute file (no meaning for a directory).
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-ls:
-- |   Arguments:
-- |     maxfiles: 10 (file listing output limited)
-- |
-- |   NFS Export: /mnt/nfs/files
-- |   NFS Access: Read Lookup NoModify NoExtend NoDelete NoExecute
-- |     PERMISSION  UID   GID   SIZE     MODIFICATION TIME  FILENAME
-- |     drwxr-xr-x  1000  100   4096     2010-06-17 12:28   /mnt/nfs/files
-- |     drwxr--r--  1000  1002  4096     2010-05-14 12:58   sources
-- |     -rw-------  1000  1002  23606    2010-06-17 12:28   notes
-- |
-- |   NFS Export: /home/storage/backup
-- |   NFS Access: Read Lookup Modify Extend Delete NoExecute
-- |     PERMISSION  UID   GID   SIZE     MODIFICATION TIME  FILENAME
-- |     drwxr-xr-x  1000  100   4096     2010-06-11 22:31   /home/storage/backup
-- |     -rw-r--r--  1000  1002  0        2010-06-10 08:34   filetest
-- |     drwx------  1000  100   16384    2010-02-05 17:05   lost+found
-- |     -rw-r--r--  0     0     5        2010-06-10 11:32   rootfile
-- |_    lrwxrwxrwx  1000  1002  8        2010-06-10 08:34   symlink
--
-- @args nfs-ls.maxfiles If set, limits the amount of files returned by
--       the script. If set to 0
--       or less, all files are shown. The default value is 10.
-- @args nfs-ls.human If set to <code>1</code> or <code>true</code>,
--       shows file sizes in a human readable format with suffixes like
--       <code>KB</code> and <code>MB</code>.
-- @args nfs-ls.time Specifies which one of the last mac times to use in
--       the files attributes output. Possible values are:
-- * <code>m</code>: last modification time (mtime)
-- * <code>a</code>: last access time (atime)
-- * <code>c</code>: last change time (ctime)
-- The default value is <code>m</code> (mtime).
 
-- Created 05/28/2010 - v0.1 - combined nfs-dirlist and nfs-acls scripts
-- Revised 06/04/2010 - v0.2 - make NFS exports listing with their acls
--                             default action.
-- Revised 06/07/2010 - v0.3 - added mactimes output.
-- Revised 06/10/2010 - v0.4 - use the new library functions and list
--                             entries with their attributes.
-- Revised 06/11/2010 - v0.5 - make the mtime the default time to show.
-- Revised 06/12/2010 - v0.6 - reworked the output to use the tab
--                             library.
-- Revised 06/27/2010 - v0.7 - added NFSv3 ACCESS support.
-- Revised 06/28/2010 - v0.8 - added NFSv2 support.
-- 

author = "Patrik Karlsson, Djalal Harouni"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
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
    local low, high = string.match(nfsport.version.version, "(%d)-(%d)")
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
    local low, high = string.match(mountport.version.version, "(%d)-(%d)")
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

local function table_attributes(nfs, mount, attr)
  local file = {}

  if attr.mode then
    file.type = rpc.Util.FtypeToChar(attr.mode)
    file.mode = rpc.Util.FpermToString(attr.mode)
    file.uid = tostring(attr.uid)
    file.gid = tostring(attr.gid)
    if nfs.human then
      file.size = rpc.Util.SizeToHuman(attr.size)
    else
      file.size = tostring(attr.size)
    end
    file.time = rpc.Util.TimeToString(attr[nfs.time].seconds)
  else
    file.type = '?'
    file.mode = '?????????'
    file.uid = '?'
    file.gid = '?'
    file.size = '?'
    file.time = '?'
  end
  file.filename = mount

  return file
end

local function table_dirlist(nfs, mount, dirlist)
  local ret, files, attrs = {}, {}, {}
  local idx = 1

  for _, v in ipairs(dirlist) do
    if ((0 < nfs.maxfiles) and (#files >= nfs.maxfiles)) then
      break
    end

    if v.name ~= ".." and v.name ~= "." then
      if v.attributes then
        table.insert(files, v.name)
        attrs[files[idx]] = table_attributes(nfs, v.name, v.attributes)
        idx = idx + 1
      else
        stdnse.print_debug(1, "ERROR attributes:  %s", v.name)
      end
    end
  end

  table.sort(files)
  for _, v in pairs(files) do
    table.insert(ret, attrs[v])
  end
    
  return ret
end

-- Unmount the NFS file system and close the connections
local function unmount_nfs(mount, mnt_obj, nfs_obj)
  rpc.Helper.NfsClose(nfs_obj)
  rpc.Helper.UnmountPath(mnt_obj, mount)
end

local function nfs_ls(nfs, mount, results, access)
  local dirs, attr, acs = {}, {}, {}
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

  -- check if NFS and Mount versions are compatible
  -- RPC library will check if the Mount and NFS versions are supported
  if (nfs_comm.version == 1) then
      unmount_nfs(mount, mnt_comm, nfs_comm)
      return false, string.format("NFS v%d not supported", nfs_comm.version)
  elseif ((nfs_comm.version == 2 and mnt_comm.version > 2) or
    (nfs_comm.version == 3 and mnt_comm.version ~= 3)) then
      unmount_nfs(mount, mnt_comm, nfs_comm)
      return false, string.format("versions mismatch, NFS v%d - Mount v%d",
                                  nfs_comm.version, mnt_comm.version)
  end

  status, attr = nfsobj:GetAttr(nfs_comm, fhandle)
  if not status then
    unmount_nfs(mount, mnt_comm, nfs_comm)
    return status, attr
  end

  table.insert(results, table_attributes(nfs, mount, attr))

  if nfs_comm.version == 3 then
    status, acs = nfsobj:Access(nfs_comm, fhandle, 0x0000003F)
    if status then
      acs.str = rpc.Util.format_access(acs.mask, nfs_comm.version)
      table.insert(access, acs.str)
    end

    status, dirs = nfsobj:ReadDirPlus(nfs_comm, fhandle)
    if status then
      for _,v in ipairs(table_dirlist(nfs, mount, dirs.entries)) do
        table.insert(results, v)
      end
    end
  elseif nfs_comm.version == 2 then
    status, dirs = nfsobj:ReadDir(nfs_comm, fhandle)
    if status then
      local lookup = {}
      for _, v in ipairs(dirs.entries) do
        if ((0 < nfs.maxfiles) and (#lookup >= nfs.maxfiles)) then
           break
        end

        if v.name ~= ".." and v.name ~= "." then
          local f = {}
          status, f = nfsobj:LookUp(nfs_comm, fhandle, v.name)
          f.name = v.name
          table.insert(lookup, f)
        end
      end

      for _, v in ipairs(table_dirlist(nfs, mount, lookup)) do
        table.insert(results, v)
      end
    end
  end

  unmount_nfs(mount, mnt_comm, nfs_comm)
  return status, dirs
end

local function report(nfs, table)
  local outtab, time = tab.new(), ""

  if nfs.time == "mtime" then
    time = "MODIFICATION TIME"
  elseif nfs.time == "atime" then
    time = "ACCESS TIME"
  elseif nfs.time == "ctime" then
    time = "CHANGE TIME"
  end

  tab.add(outtab, 1, "PERMISSION")
  tab.add(outtab, 2, "UID")
  tab.add(outtab, 3, "GID")
  tab.add(outtab, 4, "SIZE")
  tab.add(outtab, 5, time)
  tab.add(outtab, 6, "FILENAME")
  tab.nextrow(outtab)

  for _,f in pairs(table) do
    local perm = f.type .. f.mode
    tab.addrow(outtab, perm, f.uid, f.gid,
               f.size, f.time, f.filename)
  end
  return tab.dump(outtab)
end

local mainaction = function(host)
  local o, results, mounts, status = {}, {}, {}
  local nfs_info =
  {
    host      = host,
    --recurs    = tonumber(nmap.registry.args['nfs-ls.recurs']) or 1,
  }

  nfs_info.version, nfs_info.maxfiles, nfs_info.time,
  nfs_info.human = stdnse.get_script_args('nfs.version',
                      'nfs-ls.maxfiles','nfs-ls.time','nfs-ls.human')

  nfs_info.maxfiles = tonumber(nfs_info.maxfiles) or 10

  if nfs_info.time == "a" or nfs_info.time == "A" then
    nfs_info.time = "atime"
  elseif nfs_info.time == "c" or nfs_info.time == "C" then
    nfs_info.time = "ctime"
  else
    nfs_info.time = "mtime"
  end

  if nfs_info.maxfiles > 0 then
    local args = {}
    args['name'] = 'Arguments:'
    table.insert(args, 
          string.format("maxfiles: %d (file listing output limited)",
                nfs_info.maxfiles))
    table.insert(o, args)
  end

  status, mounts = procedures.ShowMounts(nfs_info.host)
  if not status or mounts == nil then
    if mounts then
      return stdnse.format_output(false, mounts)
    else
      return stdnse.format_output(false, "Mount error")
    end
  end

  for _, v in ipairs(mounts) do
    local results, access, err = {}, {}
    status, err = nfs_ls(nfs_info, v.name, results, access)
    if not status then
      table.insert(o, string.format("\nNFS Export %s", v.name))
      table.insert(o, string.format("ERROR: %s", err))
    else
      table.insert(o,
            string.format("\nNFS Export: %s", results[1].filename))
      if #access ~= 0 then
        table.insert(o, string.format("NFS Access: %s", access[1]))
      end
      table.insert(o, {report(nfs_info, results)})
    end
  end

  return stdnse.format_output(true, o)
end

hostaction = function(host)
  procedures = {
    ShowMounts = function(ahost)
      local mnt_comm, status, result, mounts
      local mnt = rpc.Mount:new()
      mnt_comm = rpc.Comm:new('mountd', host.registry.nfs.mountver)
      status, result = mnt_comm:Connect(ahost, host.registry.nfs.mountport)
      if ( not(status) ) then
        stdnse.print_debug(4, "ShowMounts: %s", result)
        return false, result
      end
      status, mounts = mnt:Export(mnt_comm)
      mnt_comm:Disconnect()
      if ( not(status) ) then
        stdnse.print_debug(4, "ShowMounts: %s", mounts)
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
        stdnse.print_debug(4, "MountPath: %s", err)
        return nil, err
      end

      status, fhandle = mnt:Mount(mnt_comm, path)
      if not status then
        mnt_comm:Disconnect()
        stdnse.print_debug(4, "MountPath: %s", fhandle)
        return nil, fhandle
      end

      return mnt_comm, fhandle
    end,

    NfsOpen = function(ahost)
      local nfs_comm, status, err

      nfs_comm = rpc.Comm:new('nfs', host.registry.nfs.nfsver)
      status, err = nfs_comm:Connect(host, host.registry.nfs.nfsport)
      if not status then
        stdnse.print_debug(4, "NfsOpen: %s", err)
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
