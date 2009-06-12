description=[[
Checks if an HTTP proxy is open.

The script attempts to connect to www.google.com through the (possible) proxy and checks
for a valid HTTP response code.

Valid HTTP response codes are actually: 200, 301, 302.

If the target is an open proxy, this script causes the target to retrieve a
web page from www.google.com.
]]

---
-- @output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- |  proxy-open-http: Potentially OPEN proxy.
-- |_ Methods succesfully tested: GET HEAD CONNECT

-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- Changelog: Added explode() function. Header-only matching now works.
--   * Fixed set_timeout
--   * Fixed some \r\n's
-- 2008-10-02 Vlatko Kosturjak <kost@linux.hr>
--   * Match case-insensitively against "^Server: gws" rather than
--     case-sensitively against "^Server: GWS/".
-- 2009-05-14 Joao Correa <joao@livewire.com.br>
--   * Included tests for HEAD and CONNECT methods
--   * Included url arguments
--   * Script now checks for http response status code

author = "Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}
require "comm"
require "shortport"
require "stdnse"
require "url"

--- check function, makes checkings for all valid returned status
--- If any of the HTTP status below is found, the proxy is potentially open
--@param result connection result
--@return true if any of the status is found, otherwise false
function check(result)
	local status = false
	if string.match(result:lower(),"^http.*200.*") then return true end
	if string.match(result:lower(),"^http.*301.*") then return true end	
	if string.match(result:lower(),"^http.*302.*") then return true end
	return false
end

portrule = shortport.port_or_service({8123,3128,8000,8080},{'polipo','squid-http','http-proxy'})

action = function(host, port)
	local response
	local i
	local retval
	local supported_methods = "\nMethods succesfully tested: "
	local fstatus = false

	-- Default url = nmap.org
	-- Default host = nmap.org
	local test_url = "http://www.google.com"
	local hostname = "www.google.com"

	-- If arg url exists, use it as url
	-- If arg hurl exists, use it as host_url
	-- If arg url exists, but arg hurl doesn't, use url as host_url
	if(nmap.registry.args.openproxy and nmap.registry.args.openproxy.url) then
		test_url = nmap.registry.args.openproxy.url
		if not string.match(test_url, "^http://.*") then 
			test_url = "http://" .. test_url
			stdnse.print_debug("URL missing scheme. URL concatenated to http://")
		end
		url_table = url.parse(test_url)
		hostname = url_table.host
	end
 
	-- Trying GET method!
	req = "GET " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
	stdnse.print_debug("GET Request: " .. req)
	local status, result = comm.exchange(host, port, req, {lines=1,proto=port.protocol, timeout=10000})

	if status then	
		lstatus = check(result)
		if lstatus then	
			supported_methods = supported_methods .. "GET "
			fstatus = true
		end
	end

	-- Trying HEAD method
	req = "HEAD " .. test_url .. " HTTP/1.0\r\nHost: " .. hostname .. "\r\n\r\n"
	stdnse.print_debug("HEAD Request: " .. req)
	local status, result = comm.exchange(host, port, req, {lines=1,proto=port.protocol, timeout=10000})

	if status then
		lstatus = check(result)
		if lstatus then	
			supported_methods = supported_methods .. "HEAD "
			fstatus = true
		end
	end 

	-- Trying CONNECT method
	-- Not really sure about how correct the code below really is!
	req = "CONNECT " .. hostname .. ":80 HTTP/1.0\r\n\r\n"
	stdnse.print_debug("CONNECT Request: " .. req)
	local status, result = comm.exchange(host, port, req, {lines=1,proto=port.protocol, timeout=10000})

	if status then
		lstatus = check(result);
		if lstatus then	
			supported_methods = supported_methods .. "CONNECT"
			fstatus = true
		end
	end

	-- If any of the tests were OK, then the proxy is potentially open
	if fstatus then
		retval = "Potentially OPEN proxy.\n" .. supported_methods
		return retval
	end
	return
end
