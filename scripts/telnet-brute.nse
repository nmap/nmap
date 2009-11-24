description = [[
Tries to get Telnet login credentials by guessing usernames and passwords.

Update (Ron Bowes, November, 2009): Now uses unpwdb database. 
]]

author = 'Eddie Bell, Ron Bowes'
license = 'Same as Nmap--See http://nmap.org/book/man-legal.html'
categories = {'auth', 'intrusive'}

require('shortport')
require('stdnse')
require('strbuf')
require('comm')
require('unpwdb')

local soc
local catch = function() soc:close() end
local try = nmap.new_try(catch)

portrule = shortport.port_or_service(23, 'telnet')

local escape_cred = function(cred) 
	if cred == '' then
		return '<blank>'
	else
		return cred 
	end
end

---
-- Go through telnet's option palaver so we can get to the login prompt.
-- We just deny every options the server asks us about.
local negotiate_options = function(result, soc)
	local index, x, opttype, opt, retbuf

	index = 0
	retbuf = strbuf.new()

	while true do

		-- 255 is IAC (Interpret As Command)
		index, x = string.find(result, '\255', index)

		if not index then 
			break 
		end

		opttype = string.byte(result, index+1)
		opt = string.byte(result, index+2)

		-- don't want it! won't do it! 
		if opttype == 251 or opttype == 252 then
			opttype = 254
		elseif opttype == 253 or opttype == 254 then
			opttype = 252
		end

		retbuf = retbuf .. string.char(255)
		retbuf = retbuf .. string.char(opttype)
		retbuf = retbuf .. string.char(opt)
		index = index + 1
	end	
	soc:send(strbuf.dump(retbuf))
end

---
-- A semi-state-machine that takes action based on output from the
-- server. Through pattern matching, it tries to deem if a user/pass
-- pair is valid. Telnet does not have a way of telling the client
-- if it was authenticated....so we have to make an educated guess
local brute_line = function(line, user, pass, usent, soc)

	if (line:find 'incorrect' or line:find 'failed' or line:find 'denied' or 
            line:find 'invalid' or line:find 'bad') and usent then
		usent = false
		return 2, nil, usent 

	elseif (line:find '[/>%%%$#]+' or line:find "last login%s*:" or
	        line:find '%u:\\') and not
	       (line:find 'username%s*:' and line:find 'login%s*:') and
	       usent then
		return 1, escape_cred(user) .. ' - ' .. escape_cred(pass)  .. '\n', usent
		
	elseif line:find 'username%s*:' or line:find 'login%s*:' then
		try(soc:send(user .. '\r\0'))
		usent = true

	elseif line:find 'password%s*:' or line:find 'passcode%s*:' then
		-- fix, add 'password only' support
		if not usent then return 1, nil, usent end
		try(soc:send(pass .. '\r\0'))
	end

	return 0, nil, usent
end

--[[
Splits the input into lines and passes it to brute_line()
so it can try to login with <user> and <pass>

return value: 
	(1, user:pass)	 - valid pair
	(2, nil) 	 - invalid pair
	(3, nil)  	 - disconnected and invalid pair
	(4, nil)  	 - disconnected and didn't send pair
--]]

local brute_cred = function(user, pass, soc)
	local status, ret, value, usent, results

	usent = false ; ret = 0

	while true do
		status, results = soc:receive_lines(1)

		-- remote host disconnected
		if not status then 
			if usent then return 3 
			else return 4 
			end
		end

		if (string.byte(results, 1) == 255) then
			negotiate_options(results, soc)
		end

		results = string.lower(results)

		for line in results:gmatch '[^\r\n]+' do 
			ret, value, usent = brute_line(line, user, pass, usent, soc)
			if (ret > 0) then
				return ret, value
			end
		end
	end
	return 1, "error -> this should never happen"
end

action = function(host, port)
	local pair, status
	local user, pass, count, rbuf
	local usernames, passwords

	status, usernames = unpwdb.usernames()
	if(not(status)) then
		stdnse.format_output(false, usernames)
	end

	status, passwords = unpwdb.passwords()
	if(not(status)) then
		return stdnse.format_output(false, passwords)
	end

	pair = nil
	status = 3
	count = 0

	local opts = {timeout=4000}

	local soc, line, best_opt = comm.tryssl(host, port, "\n",opts)
  	if not soc then 
		return stdnse.format_output(false, "Unable to open connection")
	end

	-- continually try user/pass pairs (reconnecting, if we have to)
        -- until we find a valid one or we run out of pairs
	pass = passwords()
	while not (status == 1) do

		if status == 2 or status == 3 then
			user = usernames()
			if(not(user)) then
				usernames('reset')
				user = usernames()
				pass = passwords()

				if(not(pass)) then
					return stdnse.format_output(true, "No accounts found")
				end
			end

			stdnse.print_debug(2, "telnet-brute: Trying %s/%s", user, pass)
		end

		-- make sure we don't get stuck in a loop
		if status == 4 then
			count = count + 1
			if count > 3 then
				return false, nil
			end
		else
			count = 0
		end

		if status == 3 or status == 4 then
			try(soc:connect(host.ip, port.number, best_opt))
		end

		status, pair = brute_cred(user, pass, soc)
	end

	soc:close()

	return pair
end

