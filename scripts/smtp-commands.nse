description = [[
Attempts to use EHLO and HELP to gather the Extended commands supported by an
SMTP server.
]]

---
-- @usage
-- nmap --script smtp-commands.nse [--script-args smtp-commands.domain=<domain>] -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Microsoft ESMTP 6.0.3790.3959
-- | smtp-commands: SMTP.domain.com Hello [172.x.x.x], TURN, SIZE, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, X-EXPS GSSAPI NTLM LOGIN, X-EXPS=LOGIN, AUTH GSSAPI NTLM LOGIN, AUTH=LOGIN, X-LINK2STATE, XEXCH50, OK
-- |_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
--
-- @args smtp-commands.domain Define the domain to be used in the SMTP commands.

-- changelog
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
-- 1.7.0.0 - 2008-11-10
-- + Better normalization of output, remove "250 " from EHLO output,
--   don't comma-separate HELP output.
-- 2.0.0.0 - 2010-04-19
-- + Complete rewrite based off of Arturo 'Buanzo' Busleiman's SMTP open
--   relay detector script.
-- 2.0.1.0 - 2010-04-27
-- + Incorporated advice from Duarte Silva (http://seclists.org/nmap-dev/2010/q2/277)
--   - 'domain' can be specified via a script-arg
--   - removed extra EHLO command that was redundant and not needed
--   - fixed two quit()s to include a return value
-- + To reiterate, this is a blatant cut and paste job of Arturo 'Buanzo' 
--   Busleiman's SMTP open relay detector script and Duarte Silva's SMTP 
--   user enumeration script.
--   Props to them for doing what they do and letting me ride on their coattails.

author = "Jason DePriest"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require "shortport"
require "stdnse"
require "comm"

portrule = shortport.port_or_service({ 25, 465, 587 }, { "smtp", "smtps", "submission" })

ERROR_MESSAGES = {
	["EOF"] = "connection closed",
	["TIMEOUT"] = "connection timeout",
	["ERROR"] = "failed to receive data"
}

STATUS_CODES = {
	ERROR = 1,
	NOTPERMITED = 2,
	VALID = 3,
	INVALID = 4
}

---Send a command and read the response (this function does exception handling, and if an
-- exception occurs, it will close the socket).
--
--@param socket Socket used to send the command
--@param request Command to be sent
--@return False in case of failure
--@return True and the response in case of success
function do_request(socket, request)
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

		return false, (ERROR_MESSAGES[response] or "unspecified error")
	end

	return true, response
end

---Get a domain to be used in the SMTP commands that need it. If the user specified one
-- through a script argument this function will return it. Otherwise it will try to find
-- the domain from the typed hostname and from the rDNS name. If it still can't find one
-- it will use the nmap.scanme.org by default.
--
-- @param host Current scanned host
-- @return The hostname to be used
function get_domain(host)
	local result = "nmap.scanme.org"

	-- Use the user provided options.
	if (nmap.registry.args["smtp-commands.domain"] ~= nil) then
		result = nmap.registry.args["smtp-commands.domain"]
	elseif type(host) == "table" then
		if host.targetname then
			result = host.targetname
		elseif (host.name ~= "" and host.name) then
			result = host.name
		end
	end

	return result
end

function go(host, port)
	local socket = nmap.new_socket()
	local options = {
		timeout = 10000,
		recv_before = true
	}

	socket:set_timeout(5000)

	-- Be polite and when everything works out send the QUIT message.
	local quit = function()
		do_request(socket, "QUIT\r\n")
		socket:close()
	end
	
	local domain = get_domain(host)

	-- Try to connect to server.
	local response

	socket, response = comm.tryssl(host, port, string.format("EHLO %s\r\n", domain), options)

	if not socket then
		return false, string.format("Couldn't establish connection on port %i", port.number)
	end
	
	local result = {}
	local index
	local status

	local failure = function(message)
		if #result > 0 then
			table.insert(result, message)

			return true, result
		else
			return false, message
		end
	end
	
	if not string.match(response, "^250") then
		quit()
		return false
	end
	response = string.gsub(response, "250%-", "") -- 250-
	response = string.gsub(response, "250 ", "") -- 250 
	response = string.gsub(response, "\r\n", "\n") -- normalize CR LF
	response = string.gsub(response, "\n\r", "\n") -- normalize LF CR
	response = string.gsub(response, "^\n+", "") -- no initial LF
	response = string.gsub(response, "\n+$", "") -- no final LF
	response = string.gsub(response, "\n", ", ") -- LF to comma
	response = string.gsub(response, "%s+", " ") -- get rid of extra spaces
	table.insert(result,response)

	status, response = do_request(socket, "HELP\r\n")

	if not status then
		return failure(string.format("Failed to issue HELP command (%s)", response))
	end

	if not string.match(response, "^214") then
		quit()
		return false
	end
	response = string.gsub(response, "214%-", "") -- 214-
	response = string.gsub(response, "214 ", "") -- 214
	response = string.gsub(response, "^%s+", "") -- no initial space
	response = string.gsub(response, "%s+$", "") -- no final space
	response = string.gsub(response, "%s+", " ") -- get rid of extra spaces
	table.insert(result,response)

	quit()
	return true, result
end

action = function(host, port)
	local status, result = go(host, port)

	-- The go function returned false, this means that the result is a simple error message.
	if not status then
		return result
	else
		if #result > 0 then
			final = {}
			for index, test in ipairs(result) do
				table.insert(final, test)
			end
			return stdnse.strjoin("\n ", final)
		end
	end
end
