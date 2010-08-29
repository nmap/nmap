description = [[
Performs a GET request for the root folder ("/") of a web server and displays the HTTP headers returned. 
]]

---
-- @output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- |  http-headers:  
-- |  |  HTTP/1.1 200 OK
-- |  |  Date: Tue, 10 Nov 2009 01:25:11 GMT
-- |  |  Server: Apache/2.2.9 (Unix) PHP/5.2.10
-- |  |  Last-Modified: Sat, 11 Oct 2008 15:22:21 GMT
-- |  |  ETag: "90013-e3d-458fbd508c540"
-- |  |  Accept-Ranges: bytes
-- |  |  Content-Length: 3645
-- |  |  Connection: close
-- |  |  Content-Type: text/html
-- |_ |_ (Request type: HEAD)
-- 
--@args path The path to request, such as <code>/index.php</code>. Default <code>/</code>. 
--@args useget Set to force GET requests instead of HEAD. 

author = "Ron Bowes"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require "shortport"
require "http"

portrule = shortport.http

action = function(host, port)
	local path = nmap.registry.args.path
	local request_type = "HEAD"
	if(path == nil) then
		path = '/'
	end

	local status = false
	local result

	-- Check if the user didn't want HEAD to be used
	if(nmap.registry.args.useget == nil) then
		-- Try using HEAD first
		status, result = http.can_use_head(host, port, nil, path)
	end

	-- If head failed, try using GET
	if(status == false) then
		stdnse.print_debug(1, "http-headers.nse: HEAD request failed, falling back to GET")
		result = http.get(host, port, path)
		request_type = "GET"
	end

	if(result == nil) then
		if(nmap.debugging() > 0) then
			return "ERROR: Header request failed"
		else
			return nil
		end
	end

	if(result.rawheader == nil) then
		if(nmap.debugging() > 0) then
			return "ERROR: Header request didn't return a proper header"
		else
			return nil
		end
	end

	table.insert(result.rawheader, "(Request type: " .. request_type .. ")")
--	for _, header in ipairs(result.rawheader) do
--		response = response .. header .. "\n"
--	end
		
	return stdnse.format_output(true, result.rawheader)
end

