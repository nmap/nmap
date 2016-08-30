local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Resolves hostnames and adds every address (IPv4 or IPv6, depending on
Nmap mode) to Nmap's target list.  This differs from Nmap's normal
host resolution process, which only scans the first address (A or AAAA
record) returned for each host name.
]]

---
-- @usage
-- nmap --script=resolveall --script-args=newtargets,resolveall.hosts={<host1>, ...} ...
-- @args resolveall.hosts Table of hosts to resolve
-- @output
-- Pre-scan script results:
-- | resolveall:
-- |   Host 'google.com' resolves to:
-- |     74.125.39.106
-- |     74.125.39.147
-- |     74.125.39.99
-- |     74.125.39.103
-- |     74.125.39.105
-- |     74.125.39.104
-- |_  Successfully added 6 new targets
-- @xmloutput
-- <elem key="newtargets">4</elem>
-- <table key="hosts">
--   <table key="google.com">
--     <elem>74.125.39.106</elem>
--     <elem>74.125.39.147</elem>
--     <elem>74.125.39.99</elem>
--     <elem>74.125.39.103</elem>
--   </table>
-- </table>

author = "Kris Katterjohn"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


prerule = function()
  if not stdnse.get_script_args("resolveall.hosts") then
    stdnse.verbose1("Skipping '%s', missing required argument 'resolveall.hosts'.", SCRIPT_NAME)
    return false
  end
  return true
end

local addtargets = function(list)
  local sum = 0

  for _, t in ipairs(list) do
    local st, err = target.add(t)
    if st then
      sum = sum + 1
    else
      stdnse.debug1("Couldn't add target %s: %s", t, err)
    end
  end

  return sum
end

action = function()
  local hosts = stdnse.get_script_args("resolveall.hosts")

  if type(hosts) ~= "table" then
    hosts = {hosts}
  end

  local sum = 0
  local output = {}
  local xmloutput = {}
  for _, host in ipairs(hosts) do
    local status, list = nmap.resolve(host, nmap.address_family())
    if status and #list > 0 then
      if target.ALLOW_NEW_TARGETS then
        sum = sum + addtargets(list)
      end
      xmloutput[host] = list
      table.insert(output, string.format("Host '%s' resolves to:", host))
      table.insert(output, list)
    end
  end

  xmloutput = {
    hosts = xmloutput,
    newtargets = sum or 0,
  }
  if sum > 0 then
    table.insert(output, string.format("Successfully added %d new targets", sum))
  else
    table.insert(output, "Use the 'newtargets' script-arg to add the results as targets")
  end
  return xmloutput, stdnse.format_output(true, output)
end
