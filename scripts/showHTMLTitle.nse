-- dvt <diman.todorov@gmail.com>
-- Same as Nmap--See http://nmap.org/book/man-legal.html

id = "HTML title"

description = "Connects to an HTTP server and extracts the title of the default page."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "demo", "safe"}

require 'http'
require 'url'

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
	local data, result, title, protocol

	data = http.get( host, port, '/' )
	-- follow ONE redirect if host is not some other host
	if data.status == 301 or data.status == 302 then
		local url = url.parse( data.header.location )
		if url.host == host.targetname or url.host == ( host.name ~= '' and host.name ) or url.host == host.ip then
			stdnse.print_debug("showHTMLTitle.nse: Default page is located at " .. url.scheme.. "://" .. url.authority .. url.path)
			data = http.get( host, port, url.path )
		end
	end
	result = data.body

	-- watch out, this doesn't really work for all html tags
	result = string.gsub(result, "<(/?%a+)>", function(c) return "<" .. string.lower(c) .. ">" end)

	title = string.match(result, "<title>(.+)</title>")

	if title ~= nil then
		result = string.gsub(title , "[\n\r\t]", "")
		if string.len(title) > 65 then
			stdnse.print_debug("showHTMLTitle.nse: Title got truncated!");
			result = string.sub(result, 1, 62) .. "..."
		end
	else
		result = "Site doesn't have a title."
	end

	return result
end

