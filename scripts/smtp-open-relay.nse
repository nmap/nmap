description = [[
Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal
of this script is to tell if a SMTP server is vulnerable to mail relaying.

An SMTP server that works as an open relay, is a email server that does not verify if the
user is authorised to send email from the specified email address. Therefore, users would
be able to send email originating from any third-party email address that they want.

The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is
hardcoded in the source file. The script will output all the working combinations that the
server allows, or none if the server requires authentication or if there wasn't any working
combinations.

If debug is enabled and an error occurrs while testing the target host, the error will be
printed with the list of any combinations that were found prior to the error.
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
-- @args smtp-open-relay.domain Define the domain to be used in the anti-spam tests and EHLO command (default
-- is nmap.scanme.org)
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
-- 2010-02-27 Duarte Silva <duarte.silva@myf00.net>
--   + More information in the script description
--   + Script will output the reason for failed commands (at the connection level)
--   * If some combinations were already found before an error, the script will report them
-- 2010-03-07 Duarte Silva <duarte.silva@myf00.net>
--   * Fixed socket left open when receive_lines function call fails
--   * Minor comments changes
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
	-- Exception handler.
	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	-- Lets send the command.
	try(socket:send(request))

	-- Receive server response.
	local status, response = socket:receive_lines(1)

	if not status then
		-- Close the socket (the call to receive_lines doesn't use try).
		socket:close()

		-- Supported error messages.
		local messages = {
			["EOF"] = "connection closed",
			["TIMEOUT"] = "connection timeout",
			["ERROR"] = "failed to receive data"
		}

		return false, (messages[response] or "unspecified error, for more information use --script-trace")
	end

	return true, response
end

function go(host, port)
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

	-- Use the user provided options.
	if (nmap.registry.args["smtp-open-relay.domain"] ~= nil) then
		domain = nmap.registry.args["smtp-open-relay.domain"]
	end

	if (nmap.registry.args["smtp-open-relay.ip"] ~= nil) then
		ip = nmap.registry.args["smtp-open-relay.ip"]
	end
	
	-- Try to connect to server.
	local response

	socket, response = comm.tryssl(host, port, string.format("EHLO %s\r\n", domain), options)

	if not socket then
		return false, string.format("Couldn't establish connection on port %i", port.number)
	end

	-- Close socket and return if EHLO command failed.
	if not string.match(response, "^250") then
		quit()
		return false, "Failed to issue EHLO command"
	end

	-- Find out server name.
	local srvname = string.sub(response, string.find(response, '([.%w]+)', 4))
	
	-- Antispam tests.
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
	
	local result = {}
	local index
	local status
	
	-- This function is used when something goes wrong with the connection. It makes sure that
	-- if it found working combinations before the error occurred, they will be returned. If the
	-- debug flag is enabled the error message will be appended to the combinations list.
	local failure = function(message)
		if #result > 0 then
			if nmap.debugging() > 0 then
				table.insert(result, string.format("ERROR: %s", message))
			end

			return true, result
		else
			return false, message
		end
	end
	
	for index = 1, table.getn(tests), 1 do
		status, response = dorequest(socket, "RSET\r\n")

		if not status then
			return failure(string.format("Failed to issue RSET command (%s)", response))
		end

		-- If reset the envelope, doesn't work for one, wont work for others (critical command).
		if not string.match(response, "^250") then
			quit()

			if string.match(response, "^530") then
				return false, "Server isn't an open relay, authentication needed"
			else
				return false, "Unable to clear server envelope"
			end
		end

		-- Lets try to issue MAIL FROM command.
		status, response = dorequest(socket, string.format("%s\r\n", tests[index]["from"]))

		-- If this command fails to be sent, then something went wrong with the connection.
		if not status then
			return failure(string.format("Failed to issue %s command (%s)", tests[index]["from"], response))
		end

		-- If MAIL FROM failed, check if authentication is needed because all the other attempts will fail
		-- and server may disconnect because of too many commands issued without authentication.
		if string.match(response, "^530") then
			quit()
			return false, "Server isn't an open relay, authentication needed"
		-- The command was accepted (otherwise, the script will step to the next test).
		elseif string.match(response, "^250") then
			-- Lets try to actually relay.
			status, response = dorequest(socket, string.format("%s\r\n", tests[index]["to"]))

			if not status then
				return failure(string.format("Failed to issue %s command (%s)", tests[index]["to"], response))
			end

			if string.match(response, "^530") then
				quit()
				return false, "Server isn't an open relay, authentication needed"
			elseif string.match(response, "^250") then
				-- Save the working from and to combination.
				table.insert(result, string.format("%s - > %s", tests[index]["from"], tests[index]["to"]))
			end
		end
	end

	quit()
	return true, result
end

action = function(host, port)
	local status, result = go(host, port)

	-- No combinations found.
	if #result == 0 then
		return stdnse.format_output(false, "All tests failed, server doesn't seem to be an open relay")
	end

	return stdnse.format_output(status, result)
end
