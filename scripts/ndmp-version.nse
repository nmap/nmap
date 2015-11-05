local ndmp = require "ndmp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Retrieves version information from the remote Network Data Management Protocol
(ndmp) service. NDMP is a protocol intended to transport data between a NAS
device and the backup device, removing the need for the data to pass through
the backup server. The following products are known to support the protocol:
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

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}


portrule = shortport.version_port_or_service(10000, "ndmp", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

local function vendorLookup(vendor)
  if ( vendor:match("VERITAS") ) then
    return "Symantec/Veritas Backup Exec ndmp"
  else
    return vendor
  end
end

action = function(host, port)
  local helper = ndmp.Helper:new(host, port)
  local status, err = helper:connect()
  if ( not(status) ) then return fail("Failed to connect to server") end

  local hi, si
  status, hi = helper:getHostInfo()
  if ( not(status) ) then return fail("Failed to get host information from server") end

  status, si = helper:getServerInfo()
  if ( not(status) ) then return fail("Failed to get server information from server") end
  helper:close()

  local major, minor, build, smajor, sminor = hi.hostinfo.osver:match("Major Version=(%d+) Minor Version=(%d+) Build Number=(%d+) ServicePack Major=(%d+) ServicePack Minor=(%d+)")
  port.version.name = "ndmp"
  port.version.product = vendorLookup(si.serverinfo.vendor)
  port.version.ostype = hi.hostinfo.ostype
  if ( hi.hostinfo.hostname ) then
    port.version.extrainfo = ("Name: %s; "):format(hi.hostinfo.hostname)
  end
  if ( major and minor and build and smajor and sminor ) then
    port.version.extrainfo = port.version.extrainfo .. ("OS ver: %d.%d; OS Build: %d; OS Service Pack: %d"):format(major, minor, build, smajor)
  end
  nmap.set_port_version(host, port)
end
