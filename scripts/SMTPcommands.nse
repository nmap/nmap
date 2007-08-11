-- SMTP supported commands gathering script
-- Version History
-- 1.0.0.0 - 2007-06-12

-- Cribbed heavily from Thomas Buchanan's SQL version detection
-- script and from Arturo 'Buanzo' Busleiman's SMTP open relay
-- detector script.

id = "SMTP"
description = "Attempts to use EHLO to gather the Extended commands an SMTP server supports."
author = "Jason DePriest <jrdepriest@gmail.com>"
license = "See nmaps COPYING for licence"
categories = {"discovery", "intrusive"}

portrule = function(host, port)
	if (port.number == 25
		or port.number == 587
		or port.number == 465
		or port.service == "smtp")
		and port.state == "open"
		and port.protocol == "tcp"
	then
		return true
	else
		return false
	end
end

action = function(host, port)

	local socket = nmap.new_socket()
	socket:set_timeout(5000)

	local result
	local commands
	local mailservername
	local status = true

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	try(socket:connect(host.ip, port.number, port.protocol))
	result = try(socket:receive_lines(1))

	-- ASCII for "EHLO example.org\n"
	-- for some reason it wouldn't reply unless I did it like this
	local query = "\069\072\076\079\032\101\120\097"
	query = query .. "\109\112\108\101\046\111\114\103"
	query = query .. "\013\010"
	try(socket:send(query))
	result = try(socket:receive_lines(1))

	if not string.match(result, "^250") then
		socket.close()
-- TODO: use print_debug instead
		return "EHLO with errors or timeout.  Enable --script-trace to see what is happening."
	end

	result = string.gsub(result, "\050\053\048\032\079\075\013\010", "") -- 250 OK (needed to have the \r\n in there)
	result = string.gsub(result, "250%-", "") -- 250-
	result = "Responded to EHLO command\n" .. result

	return result

end
