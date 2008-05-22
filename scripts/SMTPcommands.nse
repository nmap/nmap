-- SMTP supported commands gathering script
-- Version History
-- 1.0.0.0 - 2007-06-12
-- 1.1.0.0 - 2007-10-12
-- + added HELP command in addition to EHLO
-- 1.2.0.0 - 2008-05-19
-- + made output single line, comma-delimited, instead of
--   CR LF delimited on multi-lines

-- Cribbed heavily from Thomas Buchanan's SQL version detection
-- script and from Arturo 'Buanzo' Busleiman's SMTP open relay
-- detector script.

id = "SMTP"
description = "Attempts to use EHLO and HELP to gather the Extended commands an SMTP server supports."
author = "Jason DePriest <jrdepriest@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

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
	local table1
	local nocr_regex
	
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)
	
	try(socket:connect(host.ip, port.number, port.protocol))
	result = try(socket:receive_lines(1))
	
	-- ASCII for "EHLO example.org\n"
	-- for some reason it wouldn't reply unless I did it like this
	local query = "EHLO example.org\r\n"
	try(socket:send(query))
	result1 = try(socket:receive_lines(1))
	
	if not string.match(result1, "^250") then
		socket:close()
		-- TODO: use print_debug instead
		return "EHLO with errors or timeout.  Enable --script-trace to see what is happening."
	end
	
	result1 = string.gsub(result1, "250 OK\r\n", "") -- 250 OK (needed to have the \r\n in there)
	-- get rid of the 250- at the beginning of each line in the response
	result1 = string.gsub(result1, "250%-", "") -- 250-
	result1 = string.gsub(result1,"[\r\n]+$", "") -- no final CR LF
	result1 = string.gsub(result1, "\r\n", ", ") -- CR LF to comma
	result1 = "EHLO reply: " .. result1 .. "\n"
	
	local query = "HELP\r\n"
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
	result2 = string.gsub(result1,"[\r\n]+$", "") -- no final CR LF
	result2 = string.gsub(result1, "\r\n", ", ") -- CR LF to comma
	result2 = "HELP reply: " .. result2 .. "\n"
	
	result = result1 .. result2
	
	return result
	
end