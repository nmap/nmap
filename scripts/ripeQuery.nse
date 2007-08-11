require "ipOps"

id = "RIPE query"
description = "Connects to the RIPE database, extracts and prints the role: entry for the IP."
author = "Diman Todorov <diman.todorov@gmail.com>"
license = "See nmaps COPYING for licence"

categories = {"discovery"}

hostrule = function(host, port)
	return not ipOps.isPrivate(host.ip)
end

action = function(host, port)
	local socket = nmap.new_socket()
	local status, line
	local result = ""

	socket:connect("whois.ripe.net", 43)
--	socket:connect("193.0.0.135", 43)
	socket:send(host.ip .. "\n")

	while true do
		local status, lines = socket:receive_lines(1)

		if not status then
			break
		else
			result = result .. lines
		end
	end
	socket:close()

	local value  = string.match(result, "role:(.-)\n")

	if (value == "see http://www.iana.org.") then
		value = nil
	end

	if (value == nil) then
		value = ""
	end
	
	return "IP belongs to: " .. value
end
