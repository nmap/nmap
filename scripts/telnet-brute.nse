local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local string = require "string"
local unpwdb = require "unpwdb"

description = [[
Tries to get Telnet login credentials by guessing usernames and passwords.
Username and password combinations are retrieved from the unpwdb datatabse.
Telnet servers that require only a password (but not a username) are
currently not supported.
]]

---
-- @usage
--   nmap -p 23 --script telnet-brute \
--      --script-args userdb=myusers.lst,passdb=mypwds.lst \
--      --script-args telnet-brute.timeout=8s \
--      <target>
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  telnet
-- |_telnet-brute: root - 1234
--
-- @args telnet-brute.timeout  Connection time-out timespec (default: "5s")

author = "Eddie Bell, Ron Bowes, nnposter"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {'brute', 'intrusive'}

portrule = shortport.port_or_service(23, 'telnet')


-- Miscellaneous script-wide parameters and constants
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"

local telnet_timeout      -- connection timeout (in ms) from arg_timeout
local telnet_eol = "\r\n" -- termination string for sent lines
local conn_retries = 2    -- # of retries when attempting to connect
local sess_retries = 2    -- # of retries to log in with the same credentials
local login_debug = 2     -- debug level for printing attempted credentials
local detail_debug = 3    -- debug level for printing individual login steps


---
-- Print debug messages, prepending them with the script name
--
-- @param level Verbosity level (mandatory, unlike stdnse.print_debug).
-- @param fmt Format string.
-- @param ... Arguments to format.
local print_debug = function (level, fmt, ...)
	stdnse.print_debug(level, "%s: " .. fmt, SCRIPT_NAME, ...)
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- represents a username prompt
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_username_prompt = function (str)
	return str:find 'username%s*:'
		or str:find 'login%s*:'
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- represents a password prompt
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_password_prompt = function (str)
	return str:find 'password%s*:'
		or str:find 'passcode%s*:'
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- indicates a successful login
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_login_success = function (str)
	return str:find '[/>%%%$#]%s*$'
		or str:find 'last login%s*:'
		or str:find '%u:\\'
		or str:find 'enter terminal emulation:'
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- indicates a failed login
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_login_failure = function (str)
	return str:find 'incorrect'
		or str:find 'failed'
		or str:find 'denied'
		or str:find 'invalid'
		or str:find 'bad'
end


---
-- Simple class to encapsulate connection operations
local Connection = { methods = {} }


---
-- Initialize a connection
--
-- @param host Telnet host
-- @param port Telnet port
-- @return Connection object or nil (if the operation failed)
Connection.new = function (host, port)
	local soc, data, proto = comm.tryssl(host, port, "\n", {timeout=telnet_timeout})
  	if not soc then return nil end
	return setmetatable({
				socket = soc,
				buffer = "",
				error = "",
				host = host,
				port = port,
				proto = proto
				},
			{ __index = Connection.methods } )
end


---
-- Open the connection
--
-- @param self Connection
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.connect = function (self)
	local status
	local wait = 1

	self.buffer = ""
	self.socket:set_timeout(telnet_timeout)

	for tries = 0, conn_retries do
		status, self.error = self.socket:connect(self.host, self.port, self.proto)
		if status then break end

		stdnse.sleep(wait)
		wait = 2 * wait
	end

	return status, self.error
end


---
-- Close the connection
--
-- @param self Connection
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.close = function (self)
	local status
	self.buffer = ""
	status, self.error = self.socket:close()
	return status, self.error
end


---
-- Send one line through the connection to the server
--
-- @param self Connection
-- @param line Characters to send, will be automatically terminated
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.send_line = function (self, line)
	local status
	status, self.error = self.socket:send(line .. telnet_eol)
	return status, self.error
end


---
-- Add received data to the connection buffer while taking care
-- of telnet option signalling
--
-- @param self Connection
-- @param data Data string to add to the buffer
-- @return Number of characters in the connection buffer
Connection.methods.fill_buffer = function (self, data)
	local outbuf = strbuf.new(self.buffer)
	local optbuf = strbuf.new()
	local oldpos = 0

	while true do
		-- look for IAC (Interpret As Command)
		local newpos = data:find('\255', oldpos)
		if not newpos then break end

		outbuf = outbuf .. data:sub(oldpos, newpos - 1)
		local opttype = data:byte(newpos + 1)
		local opt = data:byte(newpos + 2)

		if opttype == 251 or opttype == 252 then
			-- Telnet Will / Will Not
			-- regarding ECHO, agree with whatever the server wants
			-- (or not) to do; otherwise respond with "don't"
			opttype = opt == 1 and opttype + 2 or 254
		elseif opttype == 253 or opttype == 254 then
			-- Telnet Do / Do not
			-- I will not do whatever the server wants me to
			opttype = 252
		end

		optbuf = optbuf .. string.char(255)
				.. string.char(opttype)
				.. string.char(opt)
		oldpos = newpos + 3
	end

	self.buffer = strbuf.dump(outbuf) .. data:sub(oldpos)
	self.socket:send(strbuf.dump(optbuf))
	return self.buffer:len()
end


---
-- Return leading part of the connection buffer, up to a line termination,
-- and refill the buffer as needed
--
-- @param self Connection
-- @return String representing the first line in the buffer
Connection.methods.get_line = function (self)
	if self.buffer:len() == 0 then
		-- refill the buffer
		local t1 = os.time()
		local status, data = self.socket:receive_buf("[\r\n:>%%%$#\255].*", true)
		if not status then
			-- connection error
			self.error = data
			return nil
		end

		self:fill_buffer(data)
	end

	return self.buffer:match('^[^\r\n]*')
end


---
-- Discard leading part of the connection buffer, up to and including
-- one or more line terminations
--
-- @param self Connection
-- @return Number of characters remaining in the connection buffer
Connection.methods.discard_line = function (self)
	self.buffer = self.buffer:gsub('^[^\r\n]*[\r\n]*', '', 1)
	return self.buffer:len()
end


local state = { INIT = 0,	-- just initialized
		LOGIN_OK = 1,	-- login succeeded
		LOGIN_BAD = 2,	-- login failed
		ERROR_PWD = 3,	-- connection problem after sending username
		ERROR_USR = 4,	-- connection problem before sending username
		PWD_ONLY = 5 }	-- password-only authentication detected


---
-- Attempt to log in with a given set of credentials and return the telnet
-- session state (according to the table above)
--
-- @param conn Connection
-- @param user Username
-- @param pass Password
-- @return Resulting state of the login
local test_credentials = function (conn, user, pass)
	local usent = false

	local error_state = function ()
		if usent then
			return state.ERROR_PWD
		else
			return state.ERROR_USR
		end
	end

	while true do
		local line = conn:get_line()
		if not line then
			-- remote host disconnected
			print_debug(detail_debug, "No data received")
			return error_state()
		end
		line = line:lower()

		if usent then
			-- username has been already sent

			if line == user:lower() then
				-- ignore; remote echo of the username in effect
				conn:discard_line()

			elseif is_login_success(line) then
				-- successful login
				print_debug(detail_debug, "Login succeeded")
				return state.LOGIN_OK

			elseif is_password_prompt(line) then
				-- being prompted for a password
				conn:discard_line()
				print_debug(detail_debug, "Sending password")
				if not conn:send_line(pass) then
					return error_state()
				end

			elseif is_login_failure(line) then
				-- failed login; explicitly told so
				conn:discard_line()
				print_debug(detail_debug, "Login failed")
				return state.LOGIN_BAD

			elseif is_username_prompt(line) then
				-- failed login; prompted again for a username
				print_debug(detail_debug, "Login failed")
				return state.LOGIN_BAD

			else
				-- ignore; insignificant response line
				conn:discard_line()

			end

		else
			-- username has not yet been sent

			if is_username_prompt(line) then
				-- being prompted for a username
				conn:discard_line()
				print_debug(detail_debug, "Sending username")
				if not conn:send_line(user) then
					return error_state()
				end
				usent = true

			elseif is_password_prompt(line) then
				-- looks like 'password only' support
				print_debug(detail_debug, "Password prompt encountered")
				return state.PWD_ONLY

			else
				-- ignore; insignificant response line
				conn:discard_line()

			end

		end

	end
end


---
-- Format credentials for use in script results or debug messages
--
-- @param user Username
-- @param pass Password
-- @return String representing the printout of the credentials
local format_credentials = function (user, pass)
	return stdnse.string_or_blank(user)
		.. " - "
		.. stdnse.string_or_blank(pass)
end


action = function (host, port)

	local userstatus, usernames = unpwdb.usernames()
	if not userstatus then
		stdnse.format_output(false, usernames)
	end

	local passstatus, passwords = unpwdb.passwords()
	if not passstatus then
		return stdnse.format_output(false, passwords)
	end

	local ts, tserror = stdnse.parse_timespec(arg_timeout)
	if not ts then
		return stdnse.format_output(false, "Invalid timeout value: " .. tserror)
	end
	telnet_timeout = 1000 * ts

	local conn = Connection.new(host, port)
  	if not conn then
		return stdnse.format_output(false, "Unable to open connection")
	end

	local mystate = state.INIT
	local retries = sess_retries

	-- continually try user/pass pairs (reconnecting, if we have to)
        -- until we find a valid one or we run out of pairs or the server
	-- stops talking to us
	local user, pass
	pass = passwords()
	while mystate ~= state.LOGIN_OK do
		if mystate == state.PWD_ONLY then
			conn:close()
			return stdnse.format_output(false, "Password-only authentication detected")
		end
		if mystate == state.INIT
				or mystate == state.ERROR_PWD
				or mystate == state.ERROR_USR then
			-- the connection needs to be re-established
			if mystate ~= state.INIT then
				print_debug(detail_debug, "Connection failed")
			end
			conn:close()
			retries = retries + 1
			if retries > sess_retries then
				if mystate == state.ERROR_USR then
					-- the server stopped cooperating
					return stdnse.format_output(false, "Authentication error")
				end
				-- move onto the next user
				mystate = state.LOGIN_BAD
			end
			if not conn:connect() then
				-- cannot reconnect with the server
				return stdnse.format_output(false, "Connection error: " .. conn.error)
			end
		end

		if mystate == state.LOGIN_BAD then
			-- get the next user/password combination
			retries = 0
			user = usernames()
			if not user then
				usernames('reset')
				user = usernames()
				pass = passwords()

				if not pass then
					conn:close()
					return stdnse.format_output(true, "No accounts found")
				end
			end

			print_debug(login_debug, "Trying %s", format_credentials(user, pass))
		end

		mystate = test_credentials(conn, user, pass)
	end

	conn:close()
	return format_credentials(user, pass)
end
