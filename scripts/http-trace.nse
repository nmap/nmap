description = [[
Sends an HTTP TRACE request and shows header fields that were modified in the
response.
]]

---
-- @output
-- 80/tcp open  http
-- |  http-trace: Response differs from request.  First 5 additional lines:
-- |  Cookie: UID=d4287aa38d02f409841b4e0c0050c131...
-- |  Country: us
-- |  Ip_is_advertise_combined: yes
-- |  Ip_conntype-Confidence: -1
-- |_ Ip_line_speed: medium

-- 08/31/2007

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require "comm"
require "shortport"
require "stdnse"

--- Truncates and formats the first 5 elements of a table.
--@param tab The table to truncate.
--@return Truncated, formatted table.
local truncate = function(tab)
	local str = ""
	str = str .. tab[1] .. "\n"
	str = str .. tab[2] .. "\n"
	str = str .. tab[3] .. "\n"
	str = str .. tab[4] .. "\n"
	str = str .. tab[5] .. "\n"
	return str
end

--- Validates the HTTP response and checks for modifications.
--@param response The HTTP response from the server.
--@param original The original HTTP request sent to the server.
--@return A string describing the changes (if any) between the response and
-- request.
local validate = function(response, original)
	local start, stop
	local body

	if not response:match("HTTP/1.[01] 200") or
	   not response:match("TRACE / HTTP/1.0") then
		return
	end

	start, stop = response:find("\r\n\r\n")
	body = response:sub(stop + 1)

	if original ~= body then
		local output =  "Response differs from request.  "

		if body:match("^TRACE / HTTP/1.0\r\n") then
			local extra = body:sub(19) -- skip TRACE line
			local tab = {}

			-- Skip extra newline at the end (making sure it's there)
			extra = extra:gsub("\r\n\r\n$", "\r\n")

			tab = stdnse.strsplit("\r\n", extra)

			if #tab > 5 then
				output = output .. "First 5 additional lines:\n"
				return output .. truncate(tab)
			end

			output = output .. "Additional lines:\n"
			return output .. extra .. "\n"
		end

		-- This shouldn't happen

		output = output .. "Full response:\n"
		return output .. body .. "\n"
	end

	return
end

portrule = shortport.port_or_service({80, 8080, 443}, {"http", "https"})

action = function(host, port)
	local cmd = "TRACE / HTTP/1.0\r\n\r\n"

	local sd, response = comm.tryssl(host, port, cmd, false)
	if not sd then 
		stdnse.print_debug("Unable to open connection") 
		return
	end
	return validate(response, cmd)
end
