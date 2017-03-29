local math = require "math"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Queries a GKRellM service for monitoring information. A single round of
collection is made, showing a snapshot of information at the time of the
request.
]]

---
-- @usage
-- nmap -p 19150 <ip> --script gkrellm-info
--
-- @output
-- PORT      STATE SERVICE
-- 19150/tcp open  gkrellm
-- | gkrellm-info:
-- |   Hostname: ubu1110
-- |   System: Linux 3.0.0-12-generic
-- |   Version: gkrellmd 2.3.4
-- |   Uptime: 2 days, 1 hours, 50 minutes
-- |   Processes: Processes 354, Load 0.00, Users 3
-- |   Memory: Total 493M, Free 201M
-- |   Network
-- |     Interface  Received  Transmitted
-- |     eth0       704M      42M
-- |     lo         43M       43M
-- |   Mounts
-- |     Mount point                        Fs type                Size    Available
-- |     /                                  rootfs                 19654M  10238M
-- |     /dev                               devtmpfs               239M    239M
-- |     /run                               tmpfs                  99M     98M
-- |     /sys/fs/fuse/connections           fusectl                0M      0M
-- |     /                                  ext4                   19654M  10238M
-- |     /sys/kernel/debug                  debugfs                0M      0M
-- |     /sys/kernel/security               securityfs             0M      0M
-- |     /run/lock                          tmpfs                  5M      5M
-- |     /run/shm                           tmpfs                  247M    247M
-- |     /proc/sys/fs/binfmt_misc           binfmt_misc            0M      0M
-- |     /media/VBOXADDITIONS_4.1.12_77245  iso9660                49M     0M
-- |_    /home/paka/.gvfs                   fuse.gvfs-fuse-daemon  0M      0M
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(19150, "gkrellm", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

local long_names = {
  ["fs_mounts"] = "Mounts",
  ["net"]       = "Network",
  ["hostname"]  = "Hostname",
  ["sysname"]   = "System",
  ["version"]   = "Version",
  ["uptime"]    = "Uptime",
  ["mem"]       = "Memory",
  ["proc"]     = "Processes",
}

local order = {
  "Hostname", "System", "Version", "Uptime", "Processes", "Memory", "Network", "Mounts"
}

local function getOrderPos(tag)
  for i=1, #order do
    if ( tag.name == order[i] ) then
      return i
    elseif ( "string" == type(tag) and tag:match("^([^:]*)") == order[i] ) then
      return i
    end
  end
  return 1
end

local function decodeTag(tag, lines)
  local result = { name = long_names[tag] }
  local order

  if ( "fs_mounts" == tag ) then
    local fs_tab = tab.new(4)
    tab.addrow(fs_tab, "Mount point", "Fs type", "Size", "Available")
    for _, line in ipairs(lines) do
      if ( ".clear" ~= line ) then
        local mount, prefix, fstype, size, free, used, bs = table.unpack(stdnse.strsplit("%s", line))
        if ( size and free and mount and fstype ) then
          size = ("%dM"):format(math.ceil(tonumber(size) * tonumber(bs) / 1048576))
          free = ("%dM"):format(math.ceil(tonumber(free) * tonumber(bs) / 1048576))
          tab.addrow(fs_tab, mount, fstype, size, free)
        end
      end
    end
    table.insert(result, tab.dump(fs_tab))
  elseif ( "net" == tag ) then
    local net_tab = tab.new(3)
    tab.addrow(net_tab, "Interface", "Received", "Transmitted")
    for _, line in ipairs(lines) do
      local name, rx, tx = line:match("^([^%s]*)%s([^%s]*)%s([^%s]*)$")
      rx = ("%dM"):format(math.ceil(tonumber(rx) / 1048576))
      tx = ("%dM"):format(math.ceil(tonumber(tx) / 1048576))
      tab.addrow(net_tab, name, rx, tx)
    end
    table.insert(result, tab.dump(net_tab))
  elseif ( "hostname" == tag or "sysname" == tag or
      "version" == tag ) then
    return ("%s: %s"):format(long_names[tag], lines[1])
  elseif ( "uptime" == tag ) then
    return ("%s: %s"):format(long_names[tag], stdnse.format_time(lines[1] * 60))
  elseif ( "mem" == tag ) then
    local total, used = table.unpack(stdnse.strsplit("%s", lines[1]))
    if ( not(total) or not(used) ) then
      return
    end
    local free = math.ceil((total - used)/1048576)
    total = math.ceil(tonumber(total)/1048576)
    return  ("%s: Total %dM, Free %dM"):format(long_names[tag], total, free)
  elseif ( "proc" == tag ) then
    local procs, _, forks, load, users = table.unpack(stdnse.strsplit("%s", lines[1]))
    if ( not(procs) or not(forks) or not(load) or not(users) ) then
      return
    end
    return ("%s: Processes %d, Load %.2f, Users %d"):format(long_names[tag], procs, load, users)
  end
  return ( #result > 0 and result or nil )
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  if ( not(socket:connect(host, port)) ) then
    return fail("Failed to connect to the server")
  end

  -- If there's an error we get a response back, and only then
  local status, data = socket:receive_buf(match.pattern_limit("\n", 2048), false)
  if( status and data ~= "<error>" ) then
    return fail("An unknown error occurred, aborting ...")
  elseif ( status ) then
    status, data = socket:receive_buf(match.pattern_limit("\n", 2048), false)
    if ( status ) then
      return fail(data)
    else
      return fail("Failed to receive error message from server")
    end
  end

  if ( not(socket:send("gkrellm 2.3.4\n")) ) then
    return fail("Failed to send data to the server")
  end

  local tags = {}
  local status, tag = socket:receive_buf(match.pattern_limit("\n", 2048), false)
  while(true) do
    if ( not(status) ) then
      break
    end
    if ( not(tag:match("^<.*>$")) ) then
      stdnse.debug2("Expected tag, got: %s", tag)
      break
    else
      tag = tag:match("^<(.*)>$")
    end

    if ( tags[tag] ) then
      break
    end

    while(true) do
      local data
      status, data = socket:receive_buf(match.pattern_limit("\n", 2048), false)
      if ( not(status) ) then
        break
      end
      if ( status and data:match("^<.*>$") ) then
        tag = data
        break
      end
      tags[tag] = tags[tag] or {}
      table.insert(tags[tag], data)
    end
  end
  socket:close()

  local output = {}
  for tag in pairs(tags) do
    local result, order = decodeTag(tag, tags[tag])
    if ( result ) then
      table.insert(output, result)
    end
  end

  table.sort(output, function(a,b) return getOrderPos(a) < getOrderPos(b) end)
  return stdnse.format_output(true, output)
end
