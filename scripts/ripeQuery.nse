require "comm"
require "ipOps"

id = "RIPE query"
description = [[
Connects to the RIPE database, extracts and prints the role: entry for the IP.
\n
This script uses an external database. Your IP address and the IP address of
the target will be sent to whois.ripe.net.
]]
author = "Diman Todorov <diman.todorov@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "external"}

hostrule = function(host, port)
	return not ipOps.isPrivate(host.ip)
end

action = function(host, port)
	local status, result = comm.exchange("whois.ripe.net", 43, host.ip .. "\n")

	if not status then
		return
	end

	local value  = string.match(result, "role:(.-)\n")

	if (value == "see http://www.iana.org.") then
		value = nil
	end

	if (value == nil) then
		return
	end
	
	return "IP belongs to: " .. value:gsub("^%s*", "")
end
