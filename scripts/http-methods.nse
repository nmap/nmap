id = "HTTP allowed methods"

description = [[
Connects to an HTTP server and sends an OPTIONS request to see which HTTP methods are allowed on this server.

By default, it tells only the Methods returned by an OPTIONS request in the Allow-Header.
In some cases a method is active, but requests with this method are only allowed e. g. from
certain IP addresses. 
If http-methods.retest is set to true we also send one single request with every method found before
to see if it returns 200 OK or something other, e. g. 403 Forbidden
]]

---
-- @usage
-- nmap --script=http-methods.nse [--script-args http-methods.url-path=<URL_Path>,http-methods.retest=true|false] <target>
-- @args http-methods.url-path if You want another URL path than / just give it here (optional, defaults to /)
-- @args http-methods.retest give true if You want to perfom a separat test for each
-- HTTP method found - see @see description (optional, defaults to false)
-- @output
-- 80/tcp open  http    syn-ack Apache httpd 2.2.8 ((Ubuntu))
-- |  HTTP allowed methods: according to OPTIONS request: GET,HEAD,POST,OPTIONS,TRACE
-- |     HTTP Status for GET is 200 OK
-- |     HTTP Status for HEAD is 200 OK
-- |     HTTP Status for POST is 200 OK
-- |     HTTP Status for OPTIONS is 200 OK
-- |_    HTTP Status for TRACE is 200 OK

author = "Bernd Stroessenreuther <berny1@users.sourceforge.net>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe"}

require "stdnse"

portrule = function(host, port)
	if not (port.service == 'http' or port.service == 'https') 
	then
		return(false)
	end
	-- Don't bother running on SSL ports if we don't have SSL.
	if ((port.service == 'https' or port.version.service_tunnel == 'ssl') and not nmap.have_ssl()) 
	then
		return(false)
	end
	return(true)
end

--- cleanup function for HTTP response header
--
-- in multi line strings any lines after the first one are removed
-- if the first line contains HTTP protocol version and response code
-- only the response code itself is kept (removing "HTTP/1.? ")
-- @param some_string gives the (probably multi line) string to clean up, 
-- normally a HTTP response header
-- @returns some_string as a clean string, single line

local cleanup = function(some_string)
	if (some_string ~= nil)
	then
		some_string = string.gsub(some_string , "[\n\r].*", "")
		some_string = string.gsub(some_string, "HTTP/[0-9]\.[0-9] ", "")
	end
	return(some_string)
end

action = function(host, port)
	local socket, request, result, methods, protocol, output, httpstatus, methodsarray, i, own_httpstatus, url_path, retest_http_methods, try, catch, location

	-- default vaules for script-args
	url_path = "/"
	retest_http_methods = false

	-- evaluate script-args
	if (nmap.registry.args ~= nil)
	then
		if (nmap.registry.args["http-methods.url-path"] ~= nil)
		then
			url_path = nmap.registry.args["http-methods.url-path"]
		end
		if (nmap.registry.args["http-methods.retest"] ~= nil)
		then
			if (nmap.registry.args["http-methods.retest"] == "true")
			then
				retest_http_methods = true
			end
		end
	end

	catch = function()
		socket:close()
	end
	try = nmap.new_try(catch)

	socket = nmap.new_socket()

	if (port.service == 'https' or port.version.service_tunnel == 'ssl')
	then
		protocol = "ssl"
	else
		protocol = "tcp"
	end

	try(socket:connect(host.ip, port.number, protocol))
	request = "OPTIONS " .. url_path .. " HTTP/1.0\r\n\r\n"
	try(socket:send(request))
	result = try(socket:receive_lines(1))
	socket:close()
	
	own_httpstatus = cleanup(result)
	stdnse.print_debug("http-methods.nse: HTTP Status for OPTIONS is " .. own_httpstatus)
	methods = cleanup(string.match(result, "Allow: *(.+)[\n\r]"))

	if (methods ~= nil)
	then
		-- got methods
		output = "OPTIONS " .. url_path .. " request returned: " .. methods
	else
		-- got no methods
		output = "OPTIONS " .. url_path .. " request returned no methods but response code " .. own_httpstatus
	end

	-- retest http methods if requested
	if (retest_http_methods and methods ~= nil)
	then
		methodsarray = stdnse.strsplit(",", methods)
		for i=1, #methodsarray, 1
		do
			stdnse.print_debug("http-methods.nse: found method " .. i .. " " .. methodsarray[i])
			if (methodsarray[i] == 'OPTIONS') 
			then
				stdnse.print_debug("http-methods.nse: no need to try method OPTIONS, using status of previous request");	
				output = output .. "\n   HTTP Status for OPTIONS " .. url_path .. " is " .. own_httpstatus
			else
				stdnse.print_debug("http-methods.nse: trying method " .. methodsarray[i] .. " on " .. protocol);	

				socket = nmap.new_socket()
				try(socket:connect(host.ip, port.number, protocol))
				request = methodsarray[i] .. " " .. url_path .. " HTTP/1.0\r\n\r\n"
				try(socket:send(request))
				httpstatus = cleanup(try(socket:receive_lines(1)))
				socket:close()

				stdnse.print_debug("http-methods.nse: HTTP Status for " .. methodsarray[i] .. " " .. url_path .. " is " .. httpstatus)
				output = output .. "\n   HTTP Status for " .. methodsarray[i] .. " " .. url_path .. " is " .. httpstatus
			end
		end
	end

	return(output)
end

