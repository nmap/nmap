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

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

require 'target'

prerule = function() return target.ALLOW_NEW_TARGETS end

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
	local hosts

	for _, k in ipairs({"resolveall.hosts", "hosts"}) do
		if nmap.registry.args[k] then
			hosts = nmap.registry.args[k]
		end
	end

	if not hosts then
		stdnse.print_debug(3,
			"Skipping '%s' %s, 'resolveall.hosts' argument is missing.",
			SCRIPT_NAME, SCRIPT_TYPE)
		return
	end

	if type(hosts) ~= "table" then
		stdnse.print_debug(3,
			"Skipping '%s' %s, 'resolveall.hosts' must be a table.",
			SCRIPT_NAME, SCRIPT_TYPE)
		return
	end

	local sum = 0

	for _, host in ipairs(hosts) do
		local status, list = nmap.resolve(host, nmap.address_family())

		if status and #list > 0 then
			sum = sum + addtargets(list)
		end
	end

	if sum == 0 then
		return
	end

	return "Successfully added " .. tostring(sum) .. " new targets"
end

