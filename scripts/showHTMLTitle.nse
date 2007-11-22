-- dvt <diman.todorov@gmail.com>
-- See nmaps COPYING for licence

id = "HTML title"

description = "Connects to an HTTP server and extracts the title of the default page."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo", "safe"}

require "stdnse"

portrule = function(host, port)
	if not (port.service == 'http' or port.service == 'https') then
		return false
	end
	-- Don't bother running on SSL ports if we don't have SSL.
	if (port.service == 'https' or port.version.service_tunnel == 'ssl')
		and not nmap.have_ssl() then
		return false
	end
	return true
end

action = function(host, port)
	local socket, request, result, status, s, title, protocol

	socket = nmap.new_socket()

	if port.service == 'https' or port.version.service_tunnel == 'ssl' then
		protocol = "ssl"
	else
		protocol = "tcp"
	end

	socket:connect(host.ip, port.number, protocol )
	request = "GET / HTTP/1.0\r\n\r\n"
	socket:send(request)

	result = ""
	while true do
		status, s = socket:receive_lines(1)
		if not status then
			break
		end

		result = result .. s
	end
	socket:close()
	
	-- watch out, this doesn't really work for all html tags
	-- also string.lower consumes the /
	result = string.gsub(result, "</?(%a+)>", function(c) return "<" .. string.lower(c) .. ">" end)
	
	title = string.match(result, "<title>(.+)<title>")

	if title ~= nil then
		result = string.gsub(title , "[\n\r\t]", "")
		if string.len(title) > 50 then
			stdnse.print_debug("showHTMLTitle.nse: Title got truncated!");	
			result = string.sub(result, 1, 62) .. "..."
		end
	else
		result = "Site doesn't have a title."
	end

	return result
end

