description = [[
Attempts to get useful informations about files from NFS exports.
This script try to emulate some features of the old "ls" unix tool.

This starts by enumerating and mounting the remote NFS exports, after 
that it performs NFS GETATTR procedure call for each mounted point
in order to get it's acls.
For each mounted directory the script will try to list it's file entries
with their attributes.

Since the file attributes shown in the results are the result of the
GETATTR, READDIRPLUS procedures and all the like then these attributes
are the attributes of the local files system.

The following access permissions are only shown for the NFSv3:
o Read:     Read data from file or read a directory.
o Lookup:   Look up a name in a directory
            (no meaning for on-directory objects).
o Modify:   Rewrite existing file data or modify existing
            directory entries.
o Extend:   Write new data or add directory entries.
o Delete:   Delete an existing directory entry.
o Execute:  Execute file (no meaning for a directory).
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-ls:
-- |   Arguments:
-- |     maxfiles: 10 (file listing output limited)  time: mtime
-- |
-- |   NFS Export: /mnt/nfs/files
-- |   NFS Access: Read Lookup NoModify NoExtend NoDelete NoExecute
-- |
-- |     PERMISSION  UID   GID   SIZE     DATE              FILENAME
-- |     drwxr-xr-x  1000  100   4096     2010-06-17 12:28  /mnt/nfs/files
-- |     drwxr--r--  1000  1002  4096     2010-05-14 12:58  sources
-- |     -rw-------  1000  1002  23606    2010-06-17 12:28  notes
-- |
-- |   NFS Export: /home/storage/backup
-- |   NFS Access: Read Lookup Modify Extend Delete NoExecute
-- |
-- |     PERMISSION  UID   GID   SIZE     DATE              FILENAME
-- |     drwxr-xr-x  1000  100   4096     2010-06-11 22:31  /home/storage/backup
-- |     -rw-r--r--  1000  1002  0        2010-06-10 08:34  filetest
-- |     drwx------  1000  100   16384    2010-02-05 17:05  lost+found
-- |     -rw-r--r--  0     0     5        2010-06-10 11:32  rootfile
-- |_    lrwxrwxrwx  1000  1002  8        2010-06-10 08:34  symlink
--
-- @args nfs-ls.maxfiles If set limits the amount of files returned by
--       the script when using nfs-ls.dirlist argument. If set to zero
--       or less all files are shown. (default 10)
-- @args nfs-ls.human If set to '1' or 'true' shows the files size in
--       the human readable format.
-- @args nfs-ls.time Specifies which one of the mac times to use in the
--       files attributes output. Possible values are:
--       m    :Modification time (mtime)
--       a    :Access time (atime)
--       c    :Change time (ctime)
--       Default value is "m" mtime.
 
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

require 'shortport'
require 'rpc'
require 'tab'

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

local function table_attributes(nfs, mount, attr)
  local file = {}

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

local function nfs_ls(nfs, mount, results, access)
  local dirs, attr, acs = {}, {}, {}
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

  -- use simple chack since NFSv1 is not used anymore.
  if (mnt_comm.version ~= nfs_comm.version) then
    rpc.Helper.UnmountPath(mnt_comm, mount)
    return false, string.format("versions mismatch, nfs v%d - mount v%d",
                                nfs_comm.version, mnt_comm.version)
  end

  status, attr = nfsobj:GetAttr(nfs_comm, fhandle)
  if not status then
    rpc.Helper.NfsClose(nfs_comm)
    rpc.Helper.UnmountPath(mnt_comm, mount)
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

  rpc.Helper.NfsClose(nfs_comm)
  rpc.Helper.UnmountPath(mnt_comm, mount)
  return status, dirs
end

local function report(table)
  local outtab = tab.new(6)

  tab.nextrow(outtab)
  tab.add(outtab, 1, "    PERMISSION")
  tab.add(outtab, 2, "UID")
  tab.add(outtab, 3, "GID")
  tab.add(outtab, 4, "SIZE")
  tab.add(outtab, 5, "DATE")
  tab.add(outtab, 6, "FILENAME")

  for _,f in pairs(table) do
    local perm = "    " .. f.type .. f.mode
    tab.nextrow(outtab)
    tab.addrow(outtab, perm, f.uid, f.gid,
               f.size, f.time, f.filename)
  end
  return tab.dump(outtab)
end

action = function(host, port)
  local o, results, mounts, status = {}, {}, {}
  local vbs = nmap.verbosity()
  local nfs_info =
  {
    host      = host,
    port      = port,
    version   = nmap.registry.args['nfs.version'] or nil,
    maxfiles  = tonumber(nmap.registry.args['nfs-ls.maxfiles']) or 10,
    time      = nmap.registry.args['nfs-ls.time'] or "",
    human     = nmap.registry.args['nfs-ls.human'] or nil,
    --dirs      = nmap.registry.args['nfs-ls.dirs'] or nil,
    --recurs    = tonumber(nmap.registry.args['nfs-ls.recurs']) or 1,
  }

  if nfs_info.time == "a" or nfs_info.time == "A" then
    nfs_info.time = "atime"
  elseif nfs_info.time == "c" or nfs_info.time == "C" then
    nfs_info.time = "ctime"
  else
    nfs_info.time = "mtime"
  end

  if vbs > 1 then
    local args, str = {}, ""
    args['name'] = 'Arguments:'
    if nfs_info.maxfiles > 0 then
      str = str .. string.format("maxfiles: %d (file listing output limited) ",
                                 nfs_info.maxfiles)
    end
    table.insert(args, string.format("%s time: %s", str, nfs_info.time))
    table.insert(o, args)
  end

  status, mounts = rpc.Helper.ShowMounts(nfs_info.host, nfs_info.port)
  if not status or mounts == nil then
    return stdnse.format_output(false, mounts)
  end

  for _, v in ipairs(mounts) do
    local results, access, str, err = {}, {}, ""
    status, err = nfs_ls(nfs_info, v.name, results, access)
    if not status then
      table.insert(o, string.format("ERROR: %s", err))
    else
      str = "\n  NFS Export: " .. results[1].filename
      if #access ~= 0 then
      	str = str .. "\n  NFS Access: " .. access[1]
      end
      table.insert(o, str)
      table.insert(o, report(results))
    end
  end

  return stdnse.format_output(true, o)
end
