-- dvt <diman.todorov@gmail.com>
-- See nmaps COPYING for licence

id = "HTML title"

description = "Connects to an HTTP server and extracts the title of the default page."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo", "safe"}

portrule = function(host, port) 
	if 
		(	port.number == 80
			or port.service == "http")
		and port.protocol == "tcp" 
		and port.state == "open"
		-- and host.name ~= nil 
		-- and string.match(host.name, "www.+") 
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local url, socket, request, result, status, s, title

	url = "http://" .. host.name

	socket = nmap.new_socket()

	socket:connect(host.ip, port.number)
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
	else
		result = "Site doesn't have a title."
	end

	return result
end

