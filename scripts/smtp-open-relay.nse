description = [[
Checks if an SMTP server is an open relay.

This script attempts to relay by issuing a predefined combination of SMTP commands. The list
of commands is hardcoded. The commands used, are fuzzed like MAIL FROM and RCPT TO commands.
]]

---
-- @usage
-- nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>] -p 25,465,587 <host>
--
-- @output
-- Host script results:
-- | smtp-open-relay:  
-- |   MAIL FROM:<antispam@[10.0.1.2]> -> RCPT TO:<"relaytest@nmap.scanme.org">
-- |   MAIL FROM:<antispam@[10.0.1.2]> -> RCPT TO:<"relaytest%nmap.scanme.org">
-- |_  MAIL FROM:<antispam@[10.0.1.2]> -> RCPT TO:<nmap.scanme.org!relaytest>
--
-- @args smtp-open-relay.domain Define the domain to be used in the anti-spam tests (default is nmap.scanme.org)
-- @args smtp-open-relay.ip Use this to change the IP address to be used (default is the target IP address)
--
-- @changelog
-- 2007-05-16 Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>
--   + Added some strings to return in different places
--   * Changed "HELO www.[ourdomain]" to "EHLO [ourdomain]"
--   * Fixed some API differences
--   * The "ourdomain" variable's contents are used instead of hardcoded "insecure.org". Settable by the user.
--   * Fixed tags -> categories (reported by Jason DePriest to nmap-dev)
-- 2009-09-20 Duarte Silva <duarte.silva@myf00.net>
--   * Rewrote the script
--   + Added documentation and some more comments
--   + Parameter to define the domain to be used instead of "ourdomain" variable
--   + Parameter to define the IP address to be used instead of the target IP address
--   * Script now detects servers that enforce authentication
--   * Changed script categories from demo to discovery and intrusive
--   * Renamed "spamtest" strings to "antispam"
-- 2010-02-20 Duarte Silva <duarte.silva@myf00.net>
--   * Renamed script parameters to follow the new naming convention
--   * Fixed problem with broken connections
--   * Changed script output to show all the successful tests
--   * Changed from string concatenation to string formatting
--   + External category
--   + Now the script will issue the QUIT message as specified in the SMTP RFC
-----------------------------------------------------------------------

author = "Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive","external"}

require "shortport"
require "comm"

portrule = shortport.port_or_service({ 25, 465, 587 }, { "smtp", "smtps", "submission" })

---Send a command and read the response (this function does exception handling, and if an
-- exception occurs, it will close the socket).
--
--@param socket Socket used to send the command
--@param request Command to be sent
--@return False in case of failure
--@return True and the response in case of success
function dorequest(socket, request)
	-- Exception handler
	local catch = function()
		socket:close()
	end
	-- Try function
	local try = nmap.new_try(catch)

	-- Lets send the command
	try(socket:send(request))
	-- Receive server response
	local status, response = socket:receive_lines(1)

	if not status then
		-- Don't really care what kind of error happened
		return false
	end

	return true, response
end

function go(host, port)
	-- Script default options
	local domain = "nmap.scanme.org"
	local ip = host.ip
	local socket = nmap.new_socket()
	local options = {
		timeout = 10000,
		recv_before = true
	}

	socket:set_timeout(5000)

	-- Be polite and when everything works out send the QUIT message.
	local quit = function()
		dorequest(socket, "QUIT\r\n")
		socket:close()
	end

	-- Use the user provided options
	if (nmap.registry.args["smtp-open-relay.domain"] ~= nil) then
		domain = nmap.registry.args["smtp-open-relay.domain"]
	end

	if (nmap.registry.args["smtp-open-relay.ip"] ~= nil) then
		ip = nmap.registry.args["smtp-open-relay.ip"]
	end
	
	-- Try to connect to server
	local response

	socket, response = comm.tryssl(host, port, string.format("EHLO %s\r\n", domain), options)

	-- Failed connection attempt
	if not socket then
		return false, string.format("Couldn't establish connection on port %i", port.number)
	end

	-- Close socket and return if there's an STMP status code != 250
	if not string.match(response, "^250") then
		quit()
		return false, "Failed to issue EHLO command"
	end

	-- Find out server name
	local srvname = string.sub(response, string.find(response, '([.%w]+)', 4))
	
	local status = true

	-- Read until end of response
	while status do
		status, response = socket:receive_lines(1)
	end
	
	-- Antispam tests
	local tests = {
		{ from = "MAIL FROM:<>", to = string.format("RCPT TO:<relaytest@%s>", domain) },
		{ from = string.format("MAIL FROM:<antispam@%s>", domain), to = string.format("RCPT TO:<relaytest@%s>", domain) },
		{ from = string.format("MAIL FROM:<antispam@%s>", srvname), to = string.format("RCPT TO:<relaytest@%s>", domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<relaytest@%s>", domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<relaytest%%%s@[%s]>", domain, ip) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<relaytest%%%s@%s>", domain, srvname) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<\"relaytest@%s\">", domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<\"relaytest%%%s\">", domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<relaytest@%s@[%s]>", domain, ip) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<\"relaytest@%s\"@[%s]>", domain, ip) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<relaytest@%s@%s>", domain, srvname) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<@[%s]:relaytest@%s>", ip, domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<@%s:relaytest@%s>", srvname, domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<%s!relaytest>", domain) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<%s!relaytest@[%s]>", domain, ip) },
		{ from = string.format("MAIL FROM:<antispam@[%s]>", ip), to = string.format("RCPT TO:<%s!relaytest@%s>", domain, srvname) },
	}
	
	local combinations = {}
	local index
	
	for index = 1, table.getn(tests), 1 do
		local result, response = dorequest(socket, "RSET\r\n")

		if not result then
			return false, "Failed to issue RSET command"
		end

		-- If reset the envelope, doesn't work for one, wont work for others (critical command)
		if not string.match(response, "^250") then
			quit()
			-- Check if server needs authentication
			if string.match(response, "^530") then
				return false, "Server isnt an open relay, authentication needed"
			else
				return false, "Unable to clear server envelope"
			end
		end

		-- Lets try to issue MAIL FROM command
		result, response = dorequest(socket, tests[index]["from"] .. "\r\n")

		-- If this command fails to be sent, then something went wrong with the connection
		if not result then
			return false, "Failed to issue MAIL FROM command"
		end

		-- If MAIL FROM failed, check if authentication is needed because all the other attempts will fail
		-- and server may disconnect because of too many commands issued without authentication (more 
		-- polite and will raise less red flags)
		if string.match(response, "^530") then
			quit()
			return false, "Server isnt an open relay, authentication needed"
		-- The command was accepted (otherwise, the script will step to the next test)
		elseif string.match(response, "^250") then
			-- Lets try to actually relay
			result, response = dorequest(socket, tests[index]["to"] .. "\r\n")

			if not result then
				return false, "Failed to issue RCPT TO command"
			end

			if string.match(response, "^530") then
				quit()
				return false, "Server isnt an open relay, authentication needed"
			elseif string.match(response, "^250") then
				-- Save the working from and to
				table.insert(combinations, {from = tests[index]["from"], to = tests[index]["to"]})
			end
		end						
	end

	quit()
	return true, combinations
end

action = function(host, port)
	local status, result = go(host, port)

	-- Something went wrong in the process, return the error message
	if not status then
		return stdnse.format_output(false, result)
	end

	-- No combinations found
	if #result == 0 then
		return stdnse.format_output(false, "All tests failed, server doesn't seem to be an open relay")
	end

	local message = {}

	-- Get all the combinations that worked
	for i, combination in ipairs(result) do
		table.insert(message, string.format("%s -> %s\n", combination.from, combination.to))
	end

	return stdnse.format_output(true, message)
end
