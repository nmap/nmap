id = "HTTP allowed methods"

description = [[
Connects to an HTTP server and sends an OPTIONS request to see which
HTTP methods are allowed on this server. Optionally tests each method
individually to see if they are subject to e.g. IP address restrictions.
]]

---
-- @args http-methods.url-path The path to request. Defaults to
-- <code>/</code>.
-- @args http-methods.retest If defined, do a request using each method
-- individually and show the response code. Use of this argument can
-- make this script unsafe; for example <code>DELETE /</code> is
-- possible.
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-methods: GET,HEAD,POST,OPTIONS,TRACE
-- | GET / -> HTTP/1.1 200 OK
-- | HEAD / -> HTTP/1.1 200 OK
-- | POST / -> HTTP/1.1 200 OK
-- | OPTIONS / -> HTTP/1.1 200 OK
-- |_TRACE / -> HTTP/1.1 200 OK
--
-- @usage
-- nmap --script=http-methods.nse --script-args http-methods.retest=1 <target>
-- nmap --script=http-methods.nse --script-args http-methods.url-path=/website <target>

author = "Bernd Stroessenreuther <berny1@users.sourceforge.net>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe"}

require("http")
require("stdnse")

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

action = function(host, port)
	local url_path, retest_http_methods
	local response, methods, options_status_line, output

	-- default vaules for script-args
	url_path = nmap.registry.args["http-methods.url-path"] or "/"
	retest_http_methods = nmap.registry.args["http-methods.retest"] ~= nil

	response = http.generic_request(host, port, "OPTIONS", url_path)
	if not response.status then
		stdnse.print_debug("http-methods: OPTIONS %s failed.", url_path)
		return
	end
	-- Cache in case retest is requested.
	options_status_line = response["status-line"]
	stdnse.print_debug("http-methods.nse: HTTP Status for OPTIONS is " .. response.status)

	if not response.header["allow"] then
		return string.format("No Allow header in OPTIONS response (status code %d)", response.status)
	end

	output = { response.header["allow"] }

	-- retest http methods if requested
	if retest_http_methods then
		local methods = stdnse.strsplit(",%s*", response.header["allow"])
		local _
		for _, method in ipairs(methods) do
			local str
			if method == "OPTIONS" then
				-- Use the saved value.
				str = options_status_line
			else
				response = http.generic_request(host, port, method, url_path)
				if not response.status then
					str = "Error getting response"
				else
					str = response["status-line"]
				end
			end
			output[#output + 1] = string.format("%s %s -> %s", method, url_path, str)
		end
	end

	return stdnse.strjoin("\n", output)
end
