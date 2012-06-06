local ftp = require "ftp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks if an FTP server allows anonymous logins.

If anonymous is allowed, gets a directory listing of the root directory
and highlights writeable files.
]]

---
-- @args ftp-anon.maxlist The maximum number of files to return in the
-- directory listing. By default it is 20, or unlimited if verbosity is
-- enabled. Use a negative number to disable the limit, or
-- <code>0</code> to disable the listing entirely.
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-anon: Anonymous FTP login allowed (FTP code 230)
-- | -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
-- | d--x--x--x   2 root     root         1024 Jan 14  2002 bin
-- | d--x--x--x   2 root     root         1024 Aug 10  1999 etc
-- | drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
-- | d--x--x--x   2 root     root         1024 Jan 14  2002 lib
-- | drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
-- |_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.

author = "Eddie Bell, Rob Nicholls, Ange Gutek, David Fifield"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "auth", "safe"}


portrule = shortport.port_or_service(21, "ftp")

-- ---------------------
-- Directory listing function.
-- We ask for a PASV connexion, catch the port returned by the server, send a
-- LIST on the commands socket, connect to the data one and read the directory
-- list sent.
-- ---------------------
local function list(socket, target, max_lines)
	local status, err

	-- ask the server for a Passive Mode: it should give us a port to
	-- listen to, where it will dump the directory listing
	local buffer = stdnse.make_buffer(socket, "\r?\n")
	status, err = socket:send("PASV\r\n")
	if not status then
		return status, err
	end
	local code, message = ftp.read_reply(buffer)

	-- Compute the PASV port as given by the server
	-- The server should answer with something like
	-- 2xx Entering Passive Mode (a,b,c,d,hp,lp)
	--                           (-- IP--,PORT)
	-- PORT is (hp x 256) + lp 
	local high, low = string.match(message, "%(%d+,%d+,%d+,%d+,(%d+),(%d+)%)")
	if not high then
		return nil, string.format("Can't parse PASV response: %q", message)
	end

	local pasv_port = high * 256 + low

	-- Send the LIST command on the commands socket. "Fire and forget"; we
	-- don't need to take care of the answer on this socket.
	status, err = socket:send("LIST\r\n")
	if not status then
		return status, err
	end

	local list_socket = nmap.new_socket()
	status, err = list_socket:connect(target, pasv_port, "tcp")
	if not status then
		return status, err
	end

	local listing = {}
	while not max_lines or #listing < max_lines do
		local status, data = list_socket:receive_buf("\r?\n", false)
		if (not status and data == "EOF") or data == "" then
			break
		end
		if not status then
			return status, data
		end
		listing[#listing + 1] = data
	end

	return true, listing
end

--- Connects to the FTP server and checks if the server allows anonymous logins.
action = function(host, port)
	local socket = nmap.new_socket()
	local code, message
	local err_catch = function()
		socket:close()
	end

	local max_list = stdnse.get_script_args("ftp-anon.maxlist")
	if not max_list then
		if nmap.verbosity() == 0 then
			max_list = 20
		else
			max_list = nil
		end
	else
		max_list = tonumber(max_list)
		if max_list < 0 then
			max_list = nil
		end
	end

	local try = nmap.new_try(err_catch)

	try(socket:connect(host, port))
	local buffer = stdnse.make_buffer(socket, "\r?\n")

	-- Read banner.
	code, message = ftp.read_reply(buffer)
	if code and code == 220 then
		try(socket:send("USER anonymous\r\n"))
		code, message = ftp.read_reply(buffer)
		if code == 331 then
			-- 331: User name okay, need password.
			try(socket:send("PASS IEUser@\r\n"))
			code, message = ftp.read_reply(buffer)
		end

		if code == 332 then
			-- 332: Need account for login.
			-- This is rarely seen but may come in response to a
			-- USER or PASS command. As we're doing this
			-- anonymously, send back a blank ACCT.
			try(socket:send("ACCT\r\n"))
			code, message = ftp.read_reply(buffer)
			if code == 331 then
				-- 331: User name okay, need password.
				try(socket:send("PASS IEUser@\r\n"))
				code, message = ftp.read_reply(buffer)
			end
		end
	end

	if code and code >= 200 and code < 300 then
		-- We are primarily looking for 230: User logged in, proceed.
	else
		if not code then
			stdnse.print_debug(1, "ftp-anon: got socket error %q.", message)
		elseif code == 421 or code == 530 then
			-- Don't log known error codes.
			-- 421: Service not available, closing control connection.
			-- 530: Not logged in.
		else
			stdnse.print_debug(1, "ftp-anon: got code %d %q.", code, message)
		end
		return nil
	end

	local result = {}
	result[#result + 1] = "Anonymous FTP login allowed (FTP code " .. code .. ")"

	if not max_list or max_list > 0 then
		local status, listing = list(socket, host, max_list)
		socket:close()
	
		if not status then
			result[#result + 1] = "Can't get directory listing: " .. listing
		else
			for _, item in ipairs(listing) do
				-- Just a quick passive check on user rights.
				if string.match(item, "^[d-].......w.") then
					item = item .. " [NSE: writeable]"
				end
				result[#result + 1] = item
			end
			if max_list and #listing == max_list then
				result[#result + 1] = string.format("Only %d shown. Use --script-args %s.maxlist=-1 to see all.", #listing, SCRIPT_NAME)
			end
		end
	end

	return table.concat(result, "\n")
end
