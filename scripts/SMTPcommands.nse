-- SMTP supported commands gathering script
-- Version History
-- 1.0.0.0 - 2007-06-12
-- 1.1.0.0 - 2007-10-12
-- 	added HELP command in addition to EHLO

-- Cribbed heavily from Thomas Buchanan's SQL version detection
-- script and from Arturo 'Buanzo' Busleiman's SMTP open relay
-- detector script.

id = "SMTP"
description = "Attempts to use EHLO and HELP to gather the Extended commands an SMTP server supports."
author = "Jason DePriest <jrdepriest@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

require "shortport"

portrule = shortport.port_or_service({25, 587, 465}, "smtp")

action = function(host, port)

	local socket = nmap.new_socket()
	socket:set_timeout(5000)

	local result1
	local result2
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
        result1 = try(socket:receive_lines(1))

        if not string.match(result1, "^250") then
                socket:close()
-- TODO: use print_debug instead
                return "EHLO with errors or timeout.  Enable --script-trace to see what is happening."
        end

	-- EHLO returns a multiline result - I would like to pull out the line feeds and replace them with
	-- something nicer like commas.  But when I do that, it messes up the first two lines as well, which
	-- probably should be on their own lines.  I have not mastered the regexes for NSE yet, so maybe some day.

	-- get rid of the line that says the commnad completed successfully
        result1 = string.gsub(result1, "\050\053\048\032\079\075\013\010", "") -- 250 OK (needed to have the \r\n in there)
	-- get rid of the 250- at the beginning of each line in the response
        result1 = string.gsub(result1, "250%-", "") -- 250-
        result1 = "Responded to EHLO command\n" .. result1

	-- ASCII for "HELP\n"
	-- for some reason it wouldn't reply unless I did it like this
	local query = "\072\069\076\080\013\010"
	try(socket:send(query))
	result2 = try(socket:receive_lines(1))

	if not string.match(result2, "^214") then
		socket:close()
-- TODO: use print_debug instead
		return "HELP with errors or timeout.  Enable --script-trace to see what is happening."
	end

	-- get rid of the 214 at the beginning of the lines in the response
	result2 = string.gsub(result2, "214%-", "") -- 214-
	result2 = string.gsub(result2, "214 ", "") -- 214
	result2 = "Responded to HELP command\n" .. result2

	result = result1 .. result2

	return result

end
