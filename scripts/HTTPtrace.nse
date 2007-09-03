-- Send HTTP TRACE method and print any modifications

-- The HTTP TRACE method is used to show any modifications made by
-- intermediate servers or proxies between you and the target host.
-- This script shows these modifications, which you can use for
-- diagnostic purposes (such as testing for web server or network
-- problems).  Plus, it's just really cool :)

-- 08/31/2007

id = "HTTP TRACE"

description = "Send HTTP TRACE method and print modifications"

author = "Kris Katterjohn <katterjohn@gmail.com>"

license = "Look at Nmap's COPYING"

categories = {"discovery"}

require "shortport"
require "stdnse"

truncate = function(tab)
	local str = ""
	str = str .. tab[1] .. "\n"
	str = str .. tab[2] .. "\n"
	str = str .. tab[3] .. "\n"
	str = str .. tab[4] .. "\n"
	str = str .. tab[5] .. "\n"
	return str
end

validate = function(response, original)
	local start, stop
	local data

	if not string.match(response, "HTTP/1.[01] 200") or
	   not string.match(response, "TRACE / HTTP/1.0") then
		return
	end

	start, stop = string.find(response, "\r\n\r\n")
	data = string.sub(response, stop + 1)

	if original ~= data then
		local output =  "Response differs from request.  "

		if string.match(data, "^TRACE / HTTP/1.0\r\n") then
			local sub = string.sub(data, 19) -- skip TRACE line
			local tab = {}

			-- Skip extra newline at the end (making sure it's there)
			sub = string.gsub(sub, "\r\n\r\n$", "\r\n")

			tab = stdnse.strsplit("\r\n", sub)

			if #tab > 5 then
				output = output .. "First 5 additional lines:\n"
				return output .. truncate(tab)
			end

			output = output .. "Additional lines:\n"
			return output .. sub .. "\n"
		end

		-- This shouldn't happen

		output = output .. "Full response:\n"
		return output .. data .. "\n"
	end

	return
end

portrule = shortport.port_or_service({80, 8080}, "http")

action = function(host, port)
	local cmd, response
	local socket

	socket = nmap.new_socket()

	socket:connect(host.ip, port.number)

	cmd = "TRACE / HTTP/1.0\r\n\r\n"

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

	return validate(response, cmd)
end

