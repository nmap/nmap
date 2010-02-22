id = "HTTP allowed methods"

description = [[
Connects to an HTTP server and sends an OPTIONS request to see which
HTTP methods are allowed on this server. Optionally tests each method
individually to see if they are subject to e.g. IP address restrictions.

By default, the script will not report anything if the only methods
found are GET, HEAD, POST, or OPTIONS. If any other methods are found,
or if Nmap is run in verbose mode, then all of them are reported.
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

categories = {"default", "safe"}

require("http")
require("nmap")
require("stdnse")

-- We don't report these methods except with verbosity.
local UNINTERESTING_METHODS = {
	"GET", "HEAD", "POST", "OPTIONS"
}

local filter_out

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
	local uninteresting

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

	if nmap.verbosity() == 0 then
		uninteresting = UNINTERESTING_METHODS
	else
		uninteresting = {}
	end

	methods = stdnse.strsplit(",%s*", response.header["allow"])
	if #filter_out(methods, uninteresting) == 0 then
		return
	end

	output = { response.header["allow"] }

	-- retest http methods if requested
	if retest_http_methods then
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

local function contains(t, elem)
	local _, e
	for _, e in ipairs(t) do
		if e == elem then
			return true
		end
	end
	return false
end

function filter_out(t, filter)
	local result = {}
	local _, e, f
	for _, e in ipairs(t) do
		if not contains(filter, e) then
			result[#result + 1] = e
		end
	end
	return result
end
