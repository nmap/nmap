local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local ls = require "ls"
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

Recursive listing is not implemented.
]]

---
-- @usage
-- nmap -p 111 --script=nfs-ls <target>
-- nmap -sV --script=nfs-ls <target>
--
-- @args nfs-ls.time Specifies which one of the last mac times to use in
--       the files attributes output. Possible values are:
-- * <code>m</code>: last modification time (mtime)
-- * <code>a</code>: last access time (atime)
-- * <code>c</code>: last change time (ctime)
-- The default value is <code>m</code> (mtime).
-- @args nfs.version The NFS protocol version to use
--
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-ls:
-- |   Volume /mnt/nfs/files
-- |   access: Read Lookup NoModify NoExtend NoDelete NoExecute
-- |   PERMISSION  UID   GID   SIZE     MODIFICATION TIME  FILENAME
-- |   drwxr-xr-x  1000  100   4096     2010-06-17 12:28   /mnt/nfs/files
-- |   drwxr--r--  1000  1002  4096     2010-05-14 12:58   sources
-- |   -rw-------  1000  1002  23606    2010-06-17 12:28   notes
-- |
-- |   Volume /home/storage/backup
-- |   access: Read Lookup Modify Extend Delete NoExecute
-- |   PERMISSION  UID   GID   SIZE     MODIFICATION TIME  FILENAME
-- |   drwxr-xr-x  1000  100   4096     2010-06-11 22:31   /home/storage/backup
-- |   -rw-r--r--  1000  1002  0        2010-06-10 08:34   filetest
-- |   drwx------  1000  100   16384    2010-02-05 17:05   lost+found
-- |   -rw-r--r--  0     0     5        2010-06-10 11:32   rootfile
-- |   lrwxrwxrwx  1000  1002  8        2010-06-10 08:34   symlink
-- |_
--
-- @xmloutput
-- <table key="volumes">
--   <table>
--     <elem key="volume">/mnt/nfs/files</elem>
--     <table key="files">
--       <table>
--         <elem key="permission">drwxr-xr-x</elem>
--         <elem key="uid">1000</elem>
--         <elem key="gid">100</elem>
--         <elem key="size">4096</elem>
--         <elem key="time">2010-06-11 22:31</elem>
--         <elem key="filename">/mnt/nfs/files</elem>
--       </table>
--       <table>
--         <elem key="permission">-rw-r-&#45;r-&#45;</elem>
--         <elem key="uid">1000</elem>
--         <elem key="gid">1002</elem>
--         <elem key="size">0</elem>
--         <elem key="time">2010-06-10 08:34</elem>
--         <elem key="filename">filetest</elem>
--       </table>
--       <table>
--         <elem key="permission">drwx-&#45;&#45;&#45;&#45;&#45;</elem>
--         <elem key="uid">0</elem>
--         <elem key="gid">0</elem>
--         <elem key="size">16384</elem>
--         <elem key="time">2010-02-05 17:05</elem>
--         <elem key="filename">lost+found</elem>
--       </table>
--       <table>
--         <elem key="permission">-rw-r-&#45;r-&#45;</elem>
--         <elem key="uid">0</elem>
--         <elem key="gid">0</elem>
--         <elem key="size">5</elem>
--         <elem key="time">2010-06-10 11:32</elem>
--         <elem key="filename">rootfile</elem>
--       </table>
--       <table>
--         <elem key="permission">lrwxrwxrwx</elem>
--         <elem key="uid">1000</elem>
--         <elem key="gid">1002</elem>
--         <elem key="size">8</elem>
--         <elem key="time">2010-06-10 08:34</elem>
--         <elem key="filename">symlink</elem>
--       </table>
--     </table>
--     <table key="info">
--       <elem>access: Read Lookup NoModify NoExtend NoDelete NoExecute</elem>
--     </table>
--   </table>
-- </table>
-- <table key="total">
--   <elem key="files">5</elem>
--   <elem key="bytes">20493</elem>
-- </table>

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

author = {"Patrik Karlsson", "Djalal Harouni"}
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

    if v.attributes then
      table.insert(files, v.name)
      attrs[files[idx]] = table_attributes(nfs, v.name, v.attributes)
      idx = idx + 1
    else
      stdnse.debug1("ERROR attributes:  %s", v.name)
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

local function nfs_ls(nfs, mount, output)
  local dirs, attr, acs = {}, {}, {}
  local nfsobj = rpc.NFS:new()
  local mnt_comm, nfs_comm, fhandle

  mnt_comm, fhandle = procedures.MountPath(nfs.host, mount)
  if mnt_comm == nil then
    ls.report_error(output, fhandle)
    return false
  end

  local nfs_comm, status = procedures.NfsOpen(nfs.host)
  if nfs_comm == nil then
    rpc.Helper.UnmountPath(mnt_comm, mount)
    ls.report_error(output, status)
    return false
  end

  -- check if NFS and Mount versions are compatible
  -- RPC library will check if the Mount and NFS versions are supported
  if (nfs_comm.version == 1) then
    unmount_nfs(mount, mnt_comm, nfs_comm)
    ls.report_error(output,
      string.format("NFS v%d not supported", nfs_comm.version))
    return false
  elseif ((nfs_comm.version == 2 and mnt_comm.version > 2) or
      (nfs_comm.version == 3 and mnt_comm.version ~= 3)) then
    unmount_nfs(mount, mnt_comm, nfs_comm)
    ls.report_error(output,
      string.format("versions mismatch, NFS v%d - Mount v%d",
      nfs_comm.version, mnt_comm.version))
    return false
  end

  status, attr = nfsobj:GetAttr(nfs_comm, fhandle)
  if not status then
    unmount_nfs(mount, mnt_comm, nfs_comm)
    ls.report_error(output, attr)
    return status
  end

  if nfs_comm.version == 3 then
    status, acs = nfsobj:Access(nfs_comm, fhandle, 0x0000003F)
    if status then
      acs.str = rpc.Util.format_access(acs.mask, nfs_comm.version)
      ls.report_info(output, string.format("access: %s", acs.str))
    end

    status, dirs = nfsobj:ReadDirPlus(nfs_comm, fhandle)
    if status then
      for _,v in ipairs(table_dirlist(nfs, mount, dirs.entries)) do
        ls.add_file(output, {v.type .. v.mode, v.uid, v.gid, v.size,
          v.time, v.filename})
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

        local f = {}
        status, f = nfsobj:LookUp(nfs_comm, fhandle, v.name)
        f.name = v.name
        table.insert(lookup, f)
      end

      for _, v in ipairs(table_dirlist(nfs, mount, lookup)) do
        ls.add_file(output, {v.type .. v.mode, v.uid, v.gid, v.size,
          v.time, v.filename})
      end
    end
  end

  unmount_nfs(mount, mnt_comm, nfs_comm)
  return status
end

local mainaction = function(host)
  local results, mounts, status = {}, {}
  local nfs_info =
  {
    host      = host,
    --recurs    = tonumber(nmap.registry.args['nfs-ls.recurs']) or 1,
  }
  local output = ls.new_listing()

  nfs_info.version, nfs_info.time = stdnse.get_script_args('nfs.version',
    'nfs-ls.time')
  nfs_info.maxfiles = ls.config('maxfiles')
  nfs_info.human = ls.config('human')

  if nfs_info.time == "a" or nfs_info.time == "A" then
    nfs_info.time = "atime"
  elseif nfs_info.time == "c" or nfs_info.time == "C" then
    nfs_info.time = "ctime"
  else
    nfs_info.time = "mtime"
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
    local err
    ls.new_vol(output, v.name, true)
    status = nfs_ls(nfs_info, v.name, output)
    ls.end_vol(output)
  end

  return ls.end_listing(output)
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
