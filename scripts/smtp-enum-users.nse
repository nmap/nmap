description = [[
Attempts to enumerate the users on a SMTP server by issuing the VRFY and the EXPN
commands. If those commands aren't implemented the script will try to use the
RCPT TO command. The goal of this script is to discover all the user accounts in the
remote system.

The script will output the list of user names that were found. The script will stop
querying the SMTP server if authentication is enforced. The script will not repeat
commands that aren't implemented (VRFY and EXPN).

The user can specify which technique to use. If so the script will not use any other
techinque. To do that the user must use the smtp-enum-users.method argument with one
of the following parameters:
 - VFRY
 - EXPN
 - RCPT

If debug is enabled and an error occurrs while testing the target host, the error will be
printed with the list of any combinations that were found prior to the error.
]]

---
-- @usage
-- nmap --script smtp-user-enum.nse -p 25,465,587 <host>
--
-- @output
-- Host script results:
-- | smtp-user-enum:  
-- |   root
-- |_  test
--
-- @args smtp-enum-users.domain Define the domain to be used in the SMTP commands.
-- @args smtp-enum-users.method Define the method to be used by the script
--
-- @changelog
-- 2010-03-07 Duarte Silva <duarte.silva@myf00.net>
--   * First version ;)
-----------------------------------------------------------------------

author = "Duarte Silva <duarte.silva@myf00.net>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","external","intrusive"}

require "shortport"
require "comm"
require 'unpwdb'

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
		-- Close the socket, the call to receive_lines doesn't use try.
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

---Get a domain to be used in the SMTP commands that need it. If the user specified one
-- through a script argument this function will return it. Otherwise it will try to find
-- the domain from the typed hostname and from the rDNS name. If it still can't find one
-- it will use the nmap.scanme.org by default.
--
--@param host Current scanned host
--@return The hostname to be used
function get_hostname(host)
	local domain = "nmap.scanme.org"
	
	-- Use the user provided options.
	if (nmap.registry.args["smtp-enum-users.domain"] ~= nil) then
		domain = nmap.registry.args["smtp-enum-users.domain"]
	elseif type(host) == "table" then
		if host.targetname then
			domain = host.targetname
		elseif (host.name ~= '' and host.name) then
			domain = host.name
		end
	end

	return domain
end

function go(host, port)
	local socket = nmap.new_socket()
	local options = {
		timeout = 10000,
		recv_before = true
	}

	socket:set_timeout(5000)

	-- Get the current usernames list from the file.
	local status, nextuser = unpwdb.usernames()

	if not status then
		socket:close()
		return false, "Failed to read the user names database"
	end

	-- Be polite and when everything works out send the QUIT message.
	local quit = function()
		dorequest(socket, "QUIT\r\n")
		socket:close()
	end

	-- Get the domain to use in the commands.
	local domain = get_hostname(host)	

	-- Try to connect to server.
	local response

	socket, response = comm.tryssl(host, port, string.format("EHLO %s\r\n", domain), options)

	-- Failed connection attempt.
	if not socket then
		return false, string.format("Couldn't establish connection on port %i", port.number)
	end

	-- Close socket and return if EHLO command failed.
	if not string.match(response, "^250") then
		quit()
		return false, "Failed to issue EHLO command"
	end

	local result = {}

	-- This function is used when something goes wrong with the connection. It makes sure that
	-- if it found users before the error occurred, they will be returned. If the debug flag is
	-- enabled the error message will be appended to the user list.
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

	local ignore_vrfy, ignore_expn, ignore_rcpt, issued_from = false, false, false, false
	-- Get the method.
	if (nmap.registry.args["smtp-enum-users.method"] ~= nil) then
		local method = nmap.registry.args["smtp-enum-users.method"]
		
		if type(method) == "string" then
			if string.find(method, "^VRFY$", 0) then
				ignore_vrfy, ignore_expn, ignore_rcpt = false, true, true
			elseif string.find(method, "^EXPN$", 0) then
				ignore_vrfy, ignore_expn, ignore_rcpt = true, false, true
			elseif string.find(method, "^RCPT$", 0) then
				ignore_vrfy, ignore_expn, ignore_rcpt = true, true, false
			end
		end
	end

	-- Get the first user to be tested.
	local username = nextuser()
	
	while username do
		-- User name and hostname combinations that can be used.
		local combinations = {
			string.format("%s", username),
			string.format("%s@%s", username, domain)
		}
		local index

		if ignore_vrfy and ignore_expn and (not ignore_rcpt) then
			-- Try to find the user by issuing the MAIL FROM and RCPT TO commands (the MAIL FROM only needs
			-- to be issued one time)
			if not issued_from then
				-- Lets try to issue MAIL FROM command.
				status, response = dorequest(socket, string.format("MAIL FROM:<usertest@%s>\r\n", domain))

				-- If this command fails to be sent, then something went wrong with the connection.
				if not status then
					-- We don't go through the failure function because if the exceution gets here the two commands
					-- that would have added user names into result aren't implemented.
					return false, string.format("Failed to issue MAIL FROM:<usertest@%s> command (%s)", domain, response)
				end
				
				-- The command was accepted. There isn't the need to test for authentication enforcing because that
				-- would be noticeable in the VRFY or EXPN commands.
				if string.match(response, "^250") then
					issued_from = true
				else
					quit()
					return false, "Server did not accept the MAIL FROM command"
				end
			end

			-- If the MAIL FROM command was issued with success we can start verying users.
			if issued_from then
				for index, combination in ipairs(combinations) do
					status, response = dorequest(socket, string.format("RCPT TO:<%s>\r\n", combination))

					if not status then
						return failure(string.format("Failed to issue RCPT TO:<%s> command (%s)", combination, response))
					end

					if string.match(response, "^250") then
						-- Save the working from and to combination.
						table.insert(result, username)
						-- If we found the user with a combination, don't test the following combinations.
						break
					end
				end
				-- Get the next user name.
				username = nextuser()
			end
		else
			if not ignore_vrfy then
				for index, combination in ipairs(combinations) do
					-- Lets try to issue the command
					status, response = dorequest(socket, string.format("VRFY %s\r\n", combination))

					-- If this command fails to be sent, then something went wrong with the connection.
					if not status then
						return failure(string.format("Failed to issue VRFY %s command (%s)\n", combination, response))
					end

					-- If the command failed, check if authentication is needed because all the other attempts will fail
					-- and server may disconnect because of too many commands issued without authentication.
					if string.match(response, "^530") then
						quit()
						return false, "Couldn't perform user enumeration, authentication needed"
					elseif string.match(response, "^502") then
						-- The server doesn't implement the command.
						ignore_vrfy = true
						break
					elseif string.match(response, "^250") then
						table.insert(result, string.format("%s\n", username))
						break
					end
				end
				
				-- If the command is implemented then the user was tested successfully. Otherwise the user needs to
				-- be tested by the following technique.
				if not ignore_vrfy then
					username = nextuser()
				end
			elseif not ignore_expn then
				for index, combination in ipairs(combinations) do
					-- Lets try to issue the command
					status, response = dorequest(socket, string.format("EXPN %s\r\n", combination))

					-- If this command fails to be sent, then something went wrong with the connection.
					if not status then
						return failure(string.format("Failed to issue EXPN %s command (%s)\n", combination, response))
					end

					-- If the command failed, check if authentication is needed because all the other attempts will fail
					-- and server may disconnect because of too many commands issued without authentication.
					if string.match(response, "^530") then
						quit()
						return false, "Couldn't perform user enumeration, authentication needed"
					elseif string.match(response, "^502") then
						-- The server doesn't implement the command.
						ignore_expn = true
						break
					elseif string.match(response, "^250") then
						table.insert(result, string.format("%s\n", username))
						break
					end
				end
				
				-- If the command is implemented then the user was tested successfully. Otherwise the user needs to
				-- be tested by the following technique.
				if not ignore_expn then
					username = nextuser()
				end
			else
				-- No more techniques.
				break
			end
		end
	end
	
	quit()
	return true, result
end

action = function(host, port)
	local status, result = go(host, port)

	if #result == 0 then
		return stdnse.format_output(false, "Couldn't find any account names")
	end

	return stdnse.format_output(status, result)
end
