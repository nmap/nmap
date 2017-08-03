local ndmp = require "ndmp"
local shortport = require "shortport"
local tab = require "tab"
local stdnse = require "stdnse"

description = [[
Lists remote file systems by querying the remote device using the Network
Data Management Protocol (ndmp). NDMP is a protocol intended to transport
data between a NAS device and the backup device, removing the need for the
data to pass through the backup server. The following products are known
to support the protocol:
* Amanda
* Bacula
* CA Arcserve
* CommVault Simpana
* EMC Networker
* Hitachi Data Systems
* IBM Tivoli
* Quest Software Netvault Backup
* Symantec Netbackup
* Symantec Backup Exec
]]

---
-- @usage
-- nmap -p 10000 --script ndmp-fs-info <ip>
--
-- @output
-- PORT      STATE SERVICE REASON  VERSION
-- 10000/tcp open  ndmp    syn-ack Symantec/Veritas Backup Exec ndmp
-- | ndmp-fs-info:
-- | FS       Logical device          Physical device
-- | NTFS     C:                      Device0000
-- | NTFS     E:                      Device0000
-- | UNKNOWN  Shadow Copy Components  Device0000
-- |_UNKNOWN  System State            Device0000
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(10000, "ndmp", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local helper = ndmp.Helper:new(host, port)
  local status, msg = helper:connect()
  if ( not(status) ) then return fail("Failed to connect to server") end

  status, msg = helper:getFsInfo()
  if ( not(status) ) then return fail("Failed to get filesystem information from server") end
  if ( msg.header.error == ndmp.NDMP.ErrorType.NOT_AUTHORIZED_ERROR ) then return fail("Not authorized to get filesystem information from server") end
  helper:close()

  local result = tab.new(3)
  tab.addrow(result, "FS", "Logical device", "Physical device")

  for _, item in ipairs(msg.fsinfo) do
    if ( item.fs_logical_device and #item.fs_logical_device ~= 0 ) then
      if ( item and item.fs_type and item.fs_logical_device and item.fs_physical_device ) then
        tab.addrow(result, item.fs_type, item.fs_logical_device:gsub("?", " "), item.fs_physical_device)
      end
    end
  end

  return "\n" .. tab.dump(result)
end
