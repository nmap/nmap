description = [[
Checks if an FTP server allows anonymous logins.
]]

---
-- @output
--- Default behavior
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-anon: Anonymous FTP login allowed (FTP code 230)

author = "Eddie Bell, Rob Nicholls, Ange Gutek, David Fifield"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "auth", "safe"}

require "shortport"

portrule = shortport.port_or_service(21, "ftp")

-- Read an FTP reply and return the numeric code and the message. See RFC 959,
-- section 4.2. The buffer argument should have been created with
-- stdnse.make_buffer(socket, "\r?\n"). On error, returns nil and an error
-- message.
local function read_reply(buffer)
	local readline
	local line, err
	local code, message
	local _, p, tmp

	line, err = buffer()
	if not line then
		    return line, err
	end

	-- Single-line response?
	code, message = string.match(line, "^(%d%d%d) (.*)$")
	if code then
		return tonumber(code), message
	end

	-- Multi-line response?
	_, p, code, message = string.find(line, "^(%d%d%d)-(.*)$")
	if p then
	while true do
		line, err = buffer()
		if not line then
			return line, err
		end
		tmp = string.match(line, "^%d%d%d (.*)$")
		if tmp then
			message = message .. "\n" .. tmp
			break
		end
		message = message .. "\n" .. line
		end

		return tonumber(code), message
	end

	return nil, string.format("Unparseable response: %q", line)
end


--- Connects to the FTP server and checks if the server allows anonymous logins.
action = function(host, port)
	local socket = nmap.new_socket()
	local code, message
	local err_catch = function()
		socket:close()
	end

	local try = nmap.new_try(err_catch)

	try(socket:connect(host, port))
	buffer = stdnse.make_buffer(socket, "\r?\n")

	-- Read banner.
	code, message = read_reply(buffer)
	if code and code == 220 then
		try(socket:send("USER anonymous\r\n"))
		code, message = read_reply(buffer)
		if code == 331 then
			-- 331: User name okay, need password.
			try(socket:send("PASS IEUser@\r\n"))
			code, message = read_reply(buffer)
		end

		if code == 332 then
			-- 332: Need account for login.
			-- This is rarely seen but may come in response to a
			-- USER or PASS command. As we're doing this
			-- anonymously, send back a blank ACCT.
			try(socket:send("ACCT\r\n"))
			code, message = read_reply(buffer)
			if code == 331 then
				-- 331: User name okay, need password.
				try(socket:send("PASS IEUser@\r\n"))
				code, message = read_reply(buffer)
			end
		end
	end

	socket:close()

	if code and code >= 200 and code < 300 then
		-- We are primarily looking for 230: User logged in, proceed.
		return "Anonymous FTP login allowed (FTP code " .. code .. ")"
	elseif code == 421 then
		-- 421: Service not available, closing control connection.
	elseif code == 530 then
		-- 530: Not logged in.
	else
		if not code then
			stdnse.print_debug(1, "ftp-anon: got socket error %q.", message)
		else
			stdnse.print_debug(1, "ftp-anon: got code %d %q.", code, message)
		end
	end
end
