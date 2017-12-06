local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"
local ipOps = require "ipOps"

description = [[
Resolves hostnames and adds every address (IPv4 or IPv6, depending on
Nmap mode) to Nmap's target list.  This differs from Nmap's normal
host resolution process, which only scans the first address (A or AAAA
record) returned for each host name.

The script will run on any target provided by hostname. It can also be fed
hostnames via the <code>resolveall.hosts</code> argument. Because it adds new
targets by IP address it will not run recursively, since those new targets were
not provided by hostname. It will also not add the same IP that was initially
chosen for scanning by Nmap.
]]

---
-- @usage
-- nmap --script=resolveall --script-args=newtargets,resolveall.hosts={<host1>, ...} ...
-- nmap --script=resolveall manyaddresses.example.com
-- @args resolveall.hosts Table of hostnames to resolve
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
-- Host script results:
-- | resolveall:
-- |   Host 'chat.freenode.net' also resolves to:
-- |     94.125.182.252
-- |     185.30.166.37
-- |     162.213.39.42
-- |     193.10.255.100
-- |     139.162.227.51
-- |     195.154.200.232
-- |     164.132.77.237
-- |     185.30.166.38
-- |     130.185.232.126
-- |     38.229.70.22
-- |_  Successfully added 10 new targets
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
  return stdnse.get_script_args("resolveall.hosts")
end

hostrule = function(host)
  return host.targetname
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

preaction = function()
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
  table.insert(output, "Use the --resolve-all option to scan all resolved addresses without using this script.")
  return xmloutput, stdnse.format_output(true, output)
end

hostaction = function(host)
  local sum = 0
  local output = {}
  local status, list = nmap.resolve(host.targetname, nmap.address_family())
  if not status or #list <= 0 then
    return nil
  end
  -- Don't re-add this same IP!
  for i = #list, 1, -1 do
    if ipOps.compare_ip(list[i], "eq", host.ip) then
      table.remove(list, i)
    end
  end
  if target.ALLOW_NEW_TARGETS then
    sum = sum + addtargets(list)
  end
  table.insert(output, string.format("Host '%s' also resolves to:", host.targetname))
  table.insert(output, list)

  local xmloutput = {
    addresses = list,
    newtargets = sum or 0,
  }
  if sum > 0 then
    table.insert(output, string.format("Successfully added %d new targets", sum))
  else
    table.insert(output, "Use the 'newtargets' script-arg to add the results as targets")
  end
  table.insert(output, ("Use the --resolve-all option to scan all resolved addresses without using this script."):format(host.targetname))
  return xmloutput, stdnse.format_output(true, output)
end

local ActionsTable = {
  -- prerule: resolve via script-args
  prerule = preaction,
  -- hostrule: resolve via scanned host
  hostrule = hostaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
