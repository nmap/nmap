local coroutine = require "coroutine"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description=[[
Checks to see if an FTP server allows port scanning using the FTP bounce method.
]]
author = "Marek Majkowski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

---
-- @args ftp-bounce.username Username to log in with. Default
-- <code>"anonymous"</code>.
-- @args ftp-bounce.password Password to log in with. Default
-- <code>"IEUser@"</code>.
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-bounce: bounce working!
--
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-bounce: server forbids bouncing to low ports <1025
-- 
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- |_ftp-bounce: no banner

categories = {"default", "safe"}


portrule = shortport.service("ftp")

line_iterate = function(s)
	local line
	for line in string.gmatch(s, "([^\n$]*)") do
		if #line > 0 then
			coroutine.yield(line)
		end
	end
end

-- returns last ftp code read, or 000 on timeout
get_ftp_code = function(socket)
	local fcode = 000
	local code  = 0
	local status
	local result
	local co
	local line
	local err

	while true do
		status, result = socket:receive()
		if not status then
			break
		end
		-- read okay!
		co = coroutine.create(line_iterate)
		while coroutine.status(co) ~= 'dead' do
			err, line = coroutine.resume(co, result)
			if line then
				code = string.match(line, "^(%d%d%d) ")
				if not code then
					code = "-1"
				end
				-- io.write(">" .. code .. ":".. line .. "<\n")
				if tonumber(code) > 0 then
					fcode = tonumber(code)
				end
			end
		end
		-- not received good ftp code, try again
		if fcode ~= 0 then
			break
		end
	end
	-- io.write("## " .. fcode .. "\n");
	return fcode
end

local get_login = function()
	local user, pass
	local k

	for _, k in ipairs({"ftp-bounce.username", "username"}) do
		if nmap.registry.args[k] then
			user = nmap.registry.args[k]
			break
		end
	end

	for _, k in ipairs({"ftp-bounce.password", "password"}) do
		if nmap.registry.args[k] then
			pass = nmap.registry.args[k]
			break
		end
	end

	return user or "anonymous", pass or "IEUser@"
end

action = function(host, port)
	local socket = nmap.new_socket()
	local result;
	local status = true
	local isAnon = false
	local isOk   = false
	local sendPass = true
	local user, pass = get_login()
	local fc
	
	socket:set_timeout(10000)
	socket:connect(host, port)

	-- BANNER
	fc = get_ftp_code(socket)
	if fc == 0 then
		socket:close()
		-- no banner
		return "no banner"
	end
	if fc == 421 or (fc >= 500 and fc <= 599) then
		socket:close()
	--	return "server says you are not allowed to create connection"
		return
	end
	if fc < 200 or fc > 299 then
		socket:close()
		-- bad code
	--	return "bad banner (code " .. fc .. ")"
		return
	end
	
	socket:set_timeout(5000)
	-- USER
	socket:send("USER " .. user .. "\r\n")
	fc = get_ftp_code(socket)
	if (fc >= 400 and fc <= 499) or (fc >= 500 and fc <= 599) then
		socket:close()
		-- bad code
		--return "anonymous user not allowed"
		return
	end
	if fc == 0 then
		socket:close()
		-- return "anonymous user timeouted"
		return 
	end
	if fc ~= 230 and fc ~= 331 then
		socket:close()
		-- bad code
		-- return "bad response for anonymous user (code " .. fc .. ")"
		return 
	end
	if fc == 230 then
		sendPass = false
	end

	-- PASS
	if sendPass then
		socket:send("PASS " .. pass .. "\r\n")
		fc = get_ftp_code(socket)
		if (fc >= 500 and fc <= 599) or (fc >= 400 and fc <= 499) then
			socket:close()
			-- bad code
			-- return "anonymous user/pass rejected"
			return
		end
		if fc == 0 then
			socket:close()
			-- return "anonymous pass timeouted"
			return
		end
		if fc ~= 230 and fc ~= 200 then
			socket:close()
			-- return "answer to PASS not understood (code " .. fc .. ")"
			return
		end
	end
	
	-- PORT scanme.nmap.com:highport
	socket:send("PORT 205,217,153,62,80,80\r\n")
	fc = get_ftp_code(socket)
	if (fc >= 500 and fc <= 599) then
		socket:close()
		-- return "server forbids bouncing"
		return
	end
	if fc == 0 then
		socket:close()
		-- return "PORT command timeouted"
		return
	end
	if not (fc >= 200 and fc<=299) then
		socket:close()
		-- return "PORT response not understood (code " .. fc .. ")"
		return
	end

	-- PORT scanme.nmap.com:lowport
	socket:send("PORT 205,217,153,62,0,80\r\n")
	fc = get_ftp_code(socket)
	if (fc >= 500 and fc <= 599) then
		socket:close()
		return "server forbids bouncing to low ports <1025"
	end
	if fc == 0 then
		socket:close()
		-- return "PORT command timeouted for low port"
		return
	end
	if not (fc >= 200 and fc<=299) then
		socket:close()
		-- return "PORT response not understood for low port (code " .. fc .. ")"
		return
	end

	socket:close()
	return "bounce working!"
end

