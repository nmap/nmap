description = [[
Tries to get FTP login credentials by guessing usernames and passwords.

This uses the standard unpwdb username/password list. However, in tests FTP servers are 
significantly slower than other servers when responding, so the number of usernames/passwords
can be artificially limited using script-args.

2008-11-06 Vlatko Kosturjak <kost@linux.hr>
Modified xampp-default-auth script to generic ftp-brute script

2009-09-18 Ron Bowes <ron@skullsecurity.net>
Made into an actual bruteforce script (previously, it only tried one username/password). 
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 21/tcp open  ftp     syn-ack
-- |  ftp-brute:
-- |  |  anonymous: IEUser@
-- |_ |_ test: password
--
-- @args userlimit The number of user accounts to try (default: unlimited).
-- @args passlimit The number of passwords to try (default: unlimited).
-- @args limit     Set userlimlt + passlimit at the same time.

author = "Diman Todorov, Vlatko Kosturjak, Ron Bowes"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}

require "shortport"
require "stdnse"
require "unpwdb"

portrule = shortport.port_or_service(21, "ftp")

local function get_limits()
	local userlimit = -1
	local passlimit = -1

	if(nmap.registry.args.userlimit) then
		userlimit = tonumber(nmap.registry.args.userlimit)
	end

	if(nmap.registry.args.passlimit) then
		passlimit = tonumber(nmap.registry.args.passlimit)
	end

	if(nmap.registry.args.limit) then
		userlimit = tonumber(nmap.registry.args.limit)
		passlimit = tonumber(nmap.registry.args.limit)
	end

	return userlimit, passlimit
end

local function login(host, port, user, pass)
	local status, err
	local res = ""

	-- Create a new socket
	local socket = nmap.new_socket()
	status, err = socket:connect(host.ip, port.number)
	if(not(status)) then
		socket:close()
		return false, "Couldn't connect to host: " .. err
	end

	status, err = socket:send("USER " .. user .. "\r\n")
	if(not(status)) then
		socket:close()
		return false, "Couldn't send login: " .. err
	end

	status, err = socket:send("PASS " .. pass .. "\n\n")
	if(not(status)) then
		socket:close()
		return false, "Couldn't send login: " .. err
	end

	-- Create a buffer and receive the first line
	local buffer = stdnse.make_buffer(socket, "\r?\n")
	local line = buffer()

	-- Loop over the lines
	while(line)do
		stdnse.print_debug("Received: %s", line)
		if(string.match(line, "^230")) then
			stdnse.print_debug(1, "ftp-brute: Successful login: %s/%s", user, pass)
			socket:close()
			return true, true
		elseif(string.match(line, "^530")) then
			socket:close()
			return true, false
		elseif(string.match(line, "^220")) then
		elseif(string.match(line, "^331")) then
		else
			stdnse.print_debug(1, "ftp-brute: WARNING: Unhandled response: %s", line)
		end

		line = buffer()
	end

	socket:close()
	return false, "Login didn't return a proper response"
end

local function go(host, port)
	local status, err
	local result
	local userlimit, passlimit = get_limits()
	local authcombinations = { 
		{user="anonymous", password="IEUser@"}, -- Anonymous user
		{user="nobody", password="xampp"}       -- XAMPP default ftp
	}

	-- Load accounts from unpwdb
	local usernames, username, passwords, password

	-- Load the usernames
	status, usernames = unpwdb.usernames()
	if(not(status)) then
		return false, "Couldn't load username list: " .. usernames
	end

	-- Load the passwords
	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return false, "Couldn't load password list: " .. usernames
	end

	-- Figure out how many 
	local i = 0
	local j = 0

	-- Add the passwords to the authcombinations table
	password = passwords()
	while (password) do
		-- Limit the passwords
		i = i + 1
		if(passlimit > 0 and i > passlimit) then
			break
		end

		j = 0
		username = usernames()
		while(username) do
			-- Limit the usernames
			j = j + 1
			if(userlimit > 0 and j > userlimit) then
				break
			end

			table.insert(authcombinations, {user=username, password=password})
			username = usernames()
		end

		usernames('reset')
		password = passwords()
	end

	stdnse.print_debug(1, "ftp-brute: Loaded %d username/password pairs", #authcombinations)

	local results = {}
	for _, combination in ipairs(authcombinations) do


		-- Attempt a login
		status, result = login(host, port, combination.user, combination.password)

		-- Check for an error
		if(not(status)) then
			return false, result
		end

		-- Check for a success
		if(status and result) then
			table.insert(results, combination)
		end
	end


	return true, results
end

action = function(host, port)
	local response = {}
	local status, results = go(host, port)

	if(not(status)) then
		return stdnse.format_output(false, results)
	end

	if(#results == 0) then
		return stdnse.format_output(false, "No accounts found")
	end

	for i, v in ipairs(results) do
		table.insert(response, string.format("%s: %s\n", v.user, v.password))
	end

	return stdnse.format_output(true, response)
end

