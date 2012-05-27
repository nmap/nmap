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

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


prerule = function()
  if not stdnse.get_script_args("resolveall.hosts") then
    stdnse.print_debug(3,
      "Skipping '%s' %s, 'resolveall.hosts' argument is missing.",
      SCRIPT_NAME, SCRIPT_TYPE)
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
			stdnse.print_debug("Couldn't add target " .. t .. ": " .. err)
		end
	end

	return sum
end

action = function()
	local hosts = stdnse.get_script_args("resolveall.hosts")

	if type(hosts) ~= "table" then
	  hosts = {hosts}
	end

	local sum, output = 0, {}
	for _, host in ipairs(hosts) do
		local status, list = nmap.resolve(host, nmap.address_family())
		if status and #list > 0 then
		    if target.ALLOW_NEW_TARGETS then
			sum = sum + addtargets(list)
		    end
	            table.insert(output,
	              string.format("Host '%s' resolves to:", host))
		    table.insert(output, list)
		end
	end

	if sum > 0 then
            table.insert(output,
              string.format("Successfully added %d new targets",
              tostring(sum)))
        else
            table.insert(output, "Use the 'newtargets' script-arg to add the results as targets")
        end
        return stdnse.format_output(true, output)
end
