local rsync = require "rsync"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Lists modules available for rsync (remote file sync) synchronization.
]]

---
-- @usage
-- nmap -p 873 --script rsync-list-modules <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 873/tcp open  rsync
-- | rsync-list-modules:
-- |   www            	www directory
-- |   log            	log directory
-- |_  etc            	etc directory
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(873, "rsync", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local helper = rsync.Helper:new(host, port, { module = "" })
  if ( not(helper) ) then
    return fail("Failed to create rsync.Helper")
  end

  local status, err = helper:connect()
  if ( not(status) ) then
    return fail("Failed to connect to rsync server")
  end

  local modules = {}
  status, modules = helper:listModules()
  if ( not(status) ) then
    return fail("Failed to retrieve a list of modules")
  end
  return stdnse.format_output(true, modules)
end
