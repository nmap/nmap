-- Connect to MySQL server and print information such as the protocol and
-- version numbers, thread id, status, capabilities and the password salt

-- If service detection is performed and the server appears to be blocking
-- our host or is blocked from too many connections, then we don't bother
-- running this script (see the portrule)

-- Many thanks to jah (jah@zadkiel.plus.com) for testing and enhancements

id = "MySQL Server Information"

description = "Connects to a MySQL server and prints information"

author = "Kris Katterjohn <katterjohn@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "discovery", "safe" }

require 'bit'

-- Grabs NUL-terminated string
local getstring = function(orig)
	local str = ""
	local index = 1

	while orig:byte(index) ~= 0 do
		str = str .. string.char(orig:byte(index))

		index = index + 1
	end

	return str
end

-- Convert two bytes into a number
local ntohs = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)

	return bit.bor(b1, bit.lshift(b2, 8))
end

-- Convert three bytes into a number
local ntoh3 = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)
	local b3 = bit.band(num:byte(3), 255)

	return bit.bor(b1, bit.lshift(b2, 8), bit.lshift(b3, 16))
end

-- Convert four bytes into a number
local ntohl = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)
	local b3 = bit.band(num:byte(3), 255)
	local b4 = bit.band(num:byte(4), 255)

	return bit.bor(b1, bit.lshift(b2, 8), bit.lshift(b3, 16), bit.lshift(b4, 24))
end

-- Convert number to a list of capabilities for printing
local capabilities = function(num)
	local caps = ""

	if bit.band(num, 1) > 0 then
		caps = caps .. "Long Passwords, "
	end

	if bit.band(num, 8) > 0 then
		caps = caps .. "Connect with DB, "
	end

	if bit.band(num, 32) > 0 then
		caps = caps .. "Compress, "
	end

	if bit.band(num, 64) > 0 then
		caps = caps .. "ODBC, "
	end

	if bit.band(num, 2048) > 0 then
		caps = caps .. "SSL, "
	end

	if bit.band(num, 8192) > 0 then
		caps = caps .. "Transactions, "
	end

	if bit.band(num, 32768) > 0 then
		caps = caps .. "Secure Connection, "
	end

	return caps:gsub(", $", "")
end

portrule = function(host, port)
	local extra = port.version.extrainfo

	if
		(port.number == 3306
		or port.service == "mysql")
		and port.protocol == "tcp"
		and port.state == "open"
		and not (extra ~= nil
			and (extra:match("[Uu]nauthorized")
				or extra:match("[Tt]oo many connection")))
	then
		return true
	end

	return false
end

action = function(host, port)
	local sock
	local response = ""
	local output = ""

	sock = nmap.new_socket()

	sock:set_timeout(5000)

	sock:connect(host.ip, port.number)

	while true do
		local status, line = sock:receive_lines(1)

		if not status then
			break
		end

		response = response .. line
	end

	sock:close()

	local length = ntoh3(response:sub(1, 3))

	if length ~= response:len() - 4 then
		return "Invalid greeting (Not MySQL?)"
	end

	-- Keeps track of where we are in the binary data
	local offset = 1 + 4

	local protocol = response:byte(offset)

	offset = offset + 1

	-- If a 0xff is here instead of the protocol, an error occurred.
	-- Pass it along to the user..
	if (protocol == 255) then
		output = "MySQL Error detected!\n"

		local sqlerrno = ntohs(response:sub(offset, offset + 2))

		offset = offset + 2

		local sqlerrstr = response:sub(offset)

		output = output .. "Error Code was: " .. sqlerrno .. "\n"

		output = output .. sqlerrstr

		return output
	end

	local version = getstring(response:sub(offset))

	offset = offset + version:len() + 1

	local threadid = ntohl(response:sub(offset, offset + 4))

	offset = offset + 4

	local salt = getstring(response:sub(offset))

	offset = offset + salt:len() + 1

	local caps = capabilities(ntohs(response:sub(offset, offset + 2)))

	offset = offset + 2

	offset = offset + 1

	local status = ""

	if ntohs(response:sub(offset, offset + 2)) == 2 then
		status = "Autocommit"
	end

	offset = offset + 2

	offset = offset + 13 -- unused

	if response:len() - offset + 1 == 13 then
		salt = salt .. getstring(response:sub(offset))
	end

	output = output .. "Protocol: " .. protocol .. "\n"
	output = output .. "Version: " .. version .. "\n"
	output = output .. "Thread ID: " .. threadid .. "\n"

	if caps:len() > 0 then
		output = output .. "Some Capabilities: " .. caps .. "\n"
	end

	if status:len() > 0 then
		output = output .. "Status: " .. status .. "\n"
	end

	output = output .. "Salt: " .. salt .. "\n"

	return output
end

