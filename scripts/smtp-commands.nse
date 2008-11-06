description = [[
Attempts to use EHLO and HELP to gather the Extended commands supported by an
SMTP server.
]]

---
-- @output
-- 25/tcp	open	smtp
-- |  smtp-commands: EHLO uninvited.example.net Hello root at localhost [127.0.0.1], SIZE 52428800, PIPELINING, 250 HELP
-- |_ HELP Commands supported:, , AUTH HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP

-- Version History
-- 1.1.0.0 - 2007-10-12
-- + added HELP command in addition to EHLO

-- 1.2.0.0 - 2008-05-19
-- + made output single line, comma-delimited, instead of
--   CR LF delimited on multi-lines
-- + was able to use regular text and not hex codes

-- 1.3.0.0 - 2008-05-21
-- + more robust handling of problems
-- + uses verbosity and debugging to decide if you need to
--   see certain errors and if the output is in a line or
--   in , for lack of a better word, fancy format
-- + I am not able to do much testing because my new ISP blocks
--   traffic going to port 25 other than to their mail servers as
--   a "security" measure.

-- 1.3.1.0 - 2008-05-22
-- + minor tweaks to get it working when one of the requests fails
--   but not both of them.

-- 1.5.0.0 - 2008-08-15
-- + updated to use the nsedoc documentation system

-- 1.6.0.0 - 2008-10-06
-- + Updated gsubs to handle different formats, pulls out extra spaces
--   and normalizes line endings

-- Cribbed heavily from Thomas Buchanan's SQL version detection
-- script and from Arturo 'Buanzo' Busleiman's SMTP open relay
-- detector script.

author = "Jason DePriest <jrdepriest@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require "shortport"
require "stdnse"

portrule = shortport.port_or_service({25, 587, 465}, "smtp")

action = function(host, port)
	
	local socket = nmap.new_socket()
	socket:set_timeout(5000)
	
	local result
	local resultEHLO
	local resultHELP
	
	local catch = function()
		socket:close()
		--return
	end
	
	local try = nmap.new_try(catch)
	
	local attempt = try(socket:connect(host.ip, port.number, port.protocol))
	if attempt then
		if nmap.verbosity() >= 2 or nmap.debugging() >= 1 then -- only tell you it fails if you are debugging or verbose X 2
			return "Problem connecting to " .. host.ip .. " on port " .. port.number .. " using protocol " .. port.protocol
		else
			return -- if you aren't debugging, just return with nothing
		end
	end
	
	result = try(socket:receive_lines(1))
	
	local query = "EHLO example.org\r\n"
	try(socket:send(query))
	resultEHLO = try(socket:receive_lines(1))
   
	if not (string.match(resultEHLO, "^250")) then
--		stdnse.print_debug("1","%s",resultEHLO)
--		stdnse.print_debug("1","EHLO with errors or timeout.  Enable --script-trace to see what is happening.")
		resultEHLO = ""
	end
	
	if resultEHLO ~= "" then
		
		resultEHLO = string.gsub(resultEHLO, "250 OK[\r\n]", "") -- 250 OK (needed to have the \r\n in there)
		-- get rid of the 250- at the beginning of each line in the response
		resultEHLO = string.gsub(resultEHLO, "250%-", "") -- 250-
		resultEHLO = string.gsub(resultEHLO, "\r\n", "\n") -- normalize CR LF
		resultEHLO = string.gsub(resultEHLO, "\n\r", "\n") -- normalize LF CR
		resultEHLO = string.gsub(resultEHLO, "\n+$", "") -- no final LF
		resultEHLO = string.gsub(resultEHLO, "\n", ", ") -- LF to comma
		resultEHLO = string.gsub(resultEHLO, "%s+", " ") -- get rid of extra spaces
		resultEHLO = "\nEHLO " .. resultEHLO
	end
	
	local query = "HELP\r\n"
	try(socket:send(query))
	resultHELP = try(socket:receive_lines(1))
	
	if not (string.match(resultHELP, "^214")) then
--		stdnse.print_debug("1","%s",resultHELP)
--		stdnse.print_debug("1","HELP with errors or timeout.  Enable --script-trace to see what is happening.")
		resultHELP = ""
	end
	if resultHELP ~= "" then
		resultHELP = string.gsub(resultHELP, "214%-", "") -- 214-
		-- get rid of the 214 at the beginning of the lines in the response
		resultHELP = string.gsub(resultHELP, "214 ", "") -- 214
		resultHELP = string.gsub(resultHELP, "\r\n", "\n") -- normalize CR LF
		resultHELP = string.gsub(resultHELP, "\n\r", "\n") -- normalize LF CR
		resultHELP = string.gsub(resultHELP, "\n+$", "") -- no final LF
		resultHELP = string.gsub(resultHELP, "\n", ", ") -- LF to comma
		resultHELP = string.gsub(resultHELP, "%s+", " ") -- get rid of extra spaces
		resultHELP = "\nHELP " .. resultHELP
	end
	
	result = resultEHLO .. resultHELP
	
	socket:close()
	
	return result
   
end
