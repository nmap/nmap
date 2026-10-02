local rsync = require "rsync"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"

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
-- |   public  Free for all storage
-- |   admin
-- |_  walter  Col. Kurtz's diaries
--
-- @xmloutput
-- <table key="public">
--   <elem key="comment">Free for all storage</elem>
-- </table>
-- <table key="admin">
--   <elem key="comment"></elem>
-- </table>
-- <table key="walter">
--   <elem key="comment">Col. Kurtz&apos;s diaries</elem>
-- </table>
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

  if not helper:connect() then
    return fail("Failed to connect to rsync server")
  end

  local status, modules = helper:listModules()
  if ( not(status) ) then
    return fail("Failed to retrieve a list of modules")
  end
  local tbl = tab.new()
  for module, params in pairs(modules) do
    tab.addrow(tbl, module, params.comment or "")
  end
  return modules, stdnse.format_output(true, tab.dump(tbl))
end
