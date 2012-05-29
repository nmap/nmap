local bit = require "bit"
local comm = require "comm"

description = [[
Connects to a MySQL server and prints information such as the protocol and
version numbers, thread ID, status, capabilities, and the password salt.

If service detection is performed and the server appears to be blocking
our host or is blocked because of too many connections, then this script
isn't run (see the portrule).
]]

---
-- @output
-- 3306/tcp open  mysql
-- |  mysql-info: Protocol: 10
-- |  Version: 5.0.51a-3ubuntu5.1
-- |  Thread ID: 7
-- |  Some Capabilities: Connect with DB, Transactions, Secure Connection
-- |  Status: Autocommit
-- |_ Salt: bYyt\NQ/4V6IN+*3`imj

-- Many thanks to jah (jah@zadkiel.plus.com) for testing and enhancements

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "default", "discovery", "safe" }


--- Grabs NUL-terminated string
--@param orig Start of the string
--@return The NUL-terminated string
local getstring = function(orig)
    return orig:match("^([^\0]*)");
end

--- Converts two bytes into a number
--@param num Start of the two bytes
--@return The converted number
local ntohs = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)

	return bit.bor(b1, bit.lshift(b2, 8))
end

--- Converts three bytes into a number
--@param num Start of the three bytes
--@return The converted number
local ntoh3 = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)
	local b3 = bit.band(num:byte(3), 255)

	return bit.bor(b1, bit.lshift(b2, 8), bit.lshift(b3, 16))
end

--- Converts four bytes into a number
--@param num Start of the four bytes
--@return The converted number
local ntohl = function(num)
	local b1 = bit.band(num:byte(1), 255)
	local b2 = bit.band(num:byte(2), 255)
	local b3 = bit.band(num:byte(3), 255)
	local b4 = bit.band(num:byte(4), 255)

	return bit.bor(b1, bit.lshift(b2, 8), bit.lshift(b3, 16), bit.lshift(b4, 24))
end

--- Converts a number to a string description of the capabilities
--@param num Start of the capabilities data
--@return String describing the capabilities offered
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

	return (port.number == 3306 or port.service == "mysql")
		and port.protocol == "tcp"
		and port.state == "open"
		and not (extra ~= nil
			and (extra:match("[Uu]nauthorized")
				or extra:match("[Tt]oo many connection")))
end

action = function(host, port)
	local output = ""

	local status, response = comm.get_banner(host, port, {timeout=5000})

	if not status then
		return
	end

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

