description = [[
Enumerates directories used by popular web applications and servers.

This parses fingerprint files that are properly formatted. Multiple files are included
with Nmap, including:
* http-fingerprints: These attempt to find common files and folders. For the most part, they were in the original http-enum.nse. 
* yokoso-fingerprints: These are application-specific fingerprints, designed for finding the presense of specific applications/hardware, including Sharepoint, Forigate's Web interface, Arcsight SmartCollector appliances, Outlook Web Access, etc. These are from the Yokoso project, by InGuardians, and included with permission from Kevin Johnson <http://seclists.org/nmap-dev/2009/q3/0685.html>. 

Initially, this script attempts to access two different random files in order to detect servers
that don't return a proper 404 Not Found status. In the event that they return 200 OK, the body
has any non-static-looking data removed (URI, time, etc), and saved. If the two random attempts
return different results, the script aborts (since a 200-looking 404 cannot be distinguished from
an actual 200). This will prevent most false positives. 

In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required, 
this script will also abort. If the root folder has disappeared or requires authentication, there
is little hope of finding anything inside it. 

By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the
script-arg <code>displayall</code> is set, however, then all results will be displayed (except
for 404 Not Found and the status code returned by the random files). 
]]

---
--@output
-- Interesting ports on test.skullsecurity.org (208.81.2.52):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |  http-enum:
-- |  /icons/ Icons and images
-- |_ /x_logo.gif Xerox Phaser Printer
-- 
--
--@args displayall Set to '1' or 'true' to display all status codes that may indicate a valid page, not just
--                 "200 OK" and "401 Authentication Required" pages. Although this is more likely to find certain
--                 hidden folders, it also generates far more false positives. 
--@args limit      Limit the number of folders to check. This option is useful if using a list from, for example, 
--                 the DirBuster projects which can have 80,000+ entries. 

author = "Ron Bowes <ron@skullsecurity.net>, Andrew Orr <andrew@andreworr.ca>, Rob Nicholls <robert@everythingeverything.co.uk>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}

require 'stdnse'
require 'http'
require 'stdnse'

---Use ssl if we have it
local have_ssl = (nmap.have_ssl() and pcall(require, "openssl"))

-- The 404 used for URL checks
local URL_404 = '/Nmap404Check' .. os.time(os.date('*t'))

-- The directory where the fingerprint files are stored
local FILENAME_BASE = "nselib/data/"

-- List of fingerprint files
local fingerprint_files = { "http-fingerprints", "yokoso-fingerprints" }

portrule = function(host, port)
	local svc = { std = { ["http"] = 1, ["http-alt"] = 1 },
				ssl = { ["https"] = 1, ["https-alt"] = 1 } }
	if port.protocol ~= 'tcp'
	or not ( svc.std[port.service] or svc.ssl[port.service] ) then
		return false
	end
	-- Don't bother running on SSL ports if we don't have SSL.
	if (svc.ssl[port.service] or port.version.service_tunnel == 'ssl')
	and not nmap.have_ssl() then
		return false
	end
	return true
end

---Take the data returned from a HTTP request and return the status string. Useful 
-- for <code>print_debug</code> messaes and even for advanced output. 
--
--@param data The data returned by a HTTP request (can be nil or empty)
--@return The status string, the status code, or "<unknown status>". 
local function get_status_string(data)
	-- Make sure we have valid data
	if(data == nil) then
		return "<unknown status>"
	elseif(data['status-line'] == nil) then
		if(data['status'] ~= nil) then
			return data['status']
		end

		return "<unknown status>"
	end

	-- We basically want everything after the space
	local space = string.find(data['status-line'], ' ')
	if(space == nil) then
		return data['status-line']
	else
		return string.sub(data['status-line'], space + 1)
	end
end

---Get the list of fingerprints from files. The files are defined in <code>fingerprint_files</code>. 
--
-- TODO: It may be a good idea, in the future, to cache them. Otherwise, these files are re-read for every 
-- host that's scanned. That can be quite a bit of i/o. 
--
--@return An array of entries, each of which have a <code>checkdir</code> field, and possibly a <code>checkdesc</code>. 
local function get_fingerprints()
	local entries  = {}
	local PREAUTH  = "# Pre-Auth"
	local POSTAUTH = "# Post-Auth"

	local i
	for i = 1, #fingerprint_files, 1 do
		local filename = FILENAME_BASE .. fingerprint_files[i]
		local filename_full = nmap.fetchfile(filename)
		local count = 0
	
		if(filename_full == nil) then
			stdnse.print_debug(1, "http-enum: Couldn't find fingerprints file: %s", filename)
		else
			stdnse.print_debug(1, "http-enum: Attempting to parse fingerprint file %s", filename)

			local product = nil
			for line in io.lines(filename) do
				-- Ignore "Pre-Auth", "Post-Auth", and blank lines
				if(string.sub(line, 1, #PREAUTH) ~= PREAUTH and string.sub(line, 1, #POSTAUTH) ~= POSTAUTH and #line > 0) then
					-- Commented lines indicate products
					if(string.sub(line, 1, 1) == "#") then
						product = string.sub(line, 3)
					else
						table.insert(entries, {checkdir=line, checkdesc=product})
						count = count + 1
					end
				end
			end
		
			stdnse.print_debug(1, "http-enum: Added %d entries from file %s", count, filename)
		end
	end
	
	return entries
end

---Determine whether or not the server supports HEAD by requesting '/' and verifying that it returns 
-- 200, and doesn't return data. We implement the check like this because can't always rely on OPTIONS to 
-- tell the truth. 
--
--Note: If <code>identify_404</code> returns a 200 status, HEAD requests should be disabled. 
--
--@param host The host object. 
--@param port The port to use -- note that SSL will automatically be used, if necessary. 
--@param result_404 [optional] The result when an unknown page is requested. This is returned by <code>identify_404</code>. 
--                  If the 404 page returns a '200' code, then we disable HEAD requests. 
--@return A boolean value: true if HEAD is usable, false otherwise. 
local function can_use_head(host, port, result_404)
	-- If the 404 result is 200, don't use HEAD. 
	if(result_404 == 200) then
		return false
	end

	-- Perform a HEAD request and see what happens. 
	local data = http.head( host, port, '/' )
	if data then
		if data.status and data.status == 302 and data.header and data.header.location then
			stdnse.print_debug(1, "http-enum.nse: Warning: Host returned 302 and not 200 when performing HEAD.")
			return false
		end

		if data.status and data.status == 200 and data.header then
			-- check that a body wasn't returned
			if string.len(data.body) > 0 then
				stdnse.print_debug(1, "http-enum.nse: Warning: Host returned data when performing HEAD.")
				return false
			end

			stdnse.print_debug(1, "http-enum.nse: Host supports HEAD.")
			return true
		end

		stdnse.print_debug(1, "http-enum.nse: Didn't receive expected response to HEAD request (got %s).", get_status_string(data))
		return false
	end

	stdnse.print_debug(1, "http-enum.nse: HEAD request completely failed.")
	return false
end

---Request the root folder, "/", in order to determine if we can use a GET request against this server. If the server returns
-- 301 Moved Permanently or 401 Authentication Required, then tests against this server will most likely fail. 
--
-- TODO: It's probably worthwhile adding a script-arg that will ignore the output of this function and always scan servers. 
--
--@param host The host object. 
--@param port The port to use -- note that SSL will automatically be used, if necessary. 
--@return (result, message) result is a boolean: true means we're good to go, false means there's an error.
--        The error is returned in message. 
local function can_use_get(host, port)
	stdnse.print_debug(1, "Checking if a GET request is going to work out")

	-- Try getting the root directory
	local data = http.get( host, port, '/' )
	if(data == nil) then
		return false, "GET request returned nil. Is the server still up?"
	end

	-- If the root directory is a permanent redirect, we're going to run into troubles
	if(data.status == 301) then
		if(data.header and data.header.location) then
			return false, string.format("GET request returned %s -- try scanning %s instead, if possible", get_status_string(data), data.header.location)
		else
			return false, string.format("GET request returned %s -- site is trying to redirect us, but didn't say where", get_status_string(data))
		end
	end

	-- If the root directory requires authentication, we're outta luck
	if(data.status == 401) then
		return false, string.format("Root directory required authentication -- giving up (%s)", get_status_string(data))
	end

	stdnse.print_debug(1, "It appears that the GET request will work")

	return true
end

---Try and remove anything that might change within a 404. For example:
-- * A file path (includes URI)
-- * A time
-- * A date
-- * An execution time (numbers in general, really)
--
-- The intention is that two 404 pages from different URIs and taken hours apart should, whenever
-- possible, look the same. 
--
-- During this function, we're likely going to over-trim things. This is fine -- we want enough to match on that it'll a) be unique, 
-- and b) have the best chance of not changing. Even if we remove bits and pieces from the file, as long as it isn't a significant
-- amount, it'll remain unique. 
--
-- One case this doesn't cover is if the server generates a random haiku for the user. 
--
--@param body The body of the page. 
--@param uri  The URI that the page came from. 
local function clean_404(body)

	-- Remove anything that looks like time 
	body = string.gsub(body, '%d?%d:%d%d:%d%d', "")
	body = string.gsub(body, '%d%d:%d%d', "")
	body = string.gsub(body, 'AM', "")
	body = string.gsub(body, 'am', "")
	body = string.gsub(body, 'PM', "")
	body = string.gsub(body, 'pm', "")

	-- Remove anything that looks like a date (this includes 6 and 8 digit numbers)
	-- (this is probably unnecessary, but it's getting pretty close to 11:59 right now, so you never know!)
	body = string.gsub(body, '%d%d%d%d%d%d%d%d', "") -- 4-digit year (has to go first, because it overlaps 2-digit year)
	body = string.gsub(body, '%d%d%d%d%-%d%d%-%d%d', "")
	body = string.gsub(body, '%d%d%d%d/%d%d/%d%d', "")
	body = string.gsub(body, '%d%d%-%d%d%-%d%d%d%d', "")
	body = string.gsub(body, '%d%d%/%d%d%/%d%d%d%d', "")

	body = string.gsub(body, '%d%d%d%d%d%d', "") -- 2-digit year
	body = string.gsub(body, '%d%d%-%d%d%-%d%d', "")
	body = string.gsub(body, '%d%d%/%d%d%/%d%d', "")

	-- Remove anything that looks like a path (note: this will get the URI too) (note2: this interferes with the date removal above, so it can't be moved up)
	body = string.gsub(body, "/[^ ]+", "") -- Unix - remove everything from a slash till the next space
	body = string.gsub(body, "[a-zA-Z]:\\[^ ]+", "") -- Windows - remove everything from a "x:\" pattern till the next space

	-- If we have SSL available, save us a lot of memory by hashing the page (if SSL isn't available, this will work fine, but
	-- take up more memory). If we're debugging, don't hash (it makes things far harder to debug). 
	if(have_ssl and nmap.debugging() == 0) then
		return openssl.md5(body)
	end

	return body
end

---Try requesting a non-existent file to determine how the server responds to unknown pages ("404 pages"), which a) 
-- tells us what to expect when a non-existent page is requested, and b) tells us if the server will be impossible to
-- scan. If the server responds with a 404 status code, as it is supposed to, then this function simply returns 404. If it 
-- contains one of a series of common status codes, including unauthorized, moved, and others, it is returned like a 404. 
--
-- If, however, the 404 page returns a 200 status code, it gets interesting. First, it attempts to clean the returned
-- body (see <code>clean_404</code> for details). Once any dynamic-looking data has been removed from the string, another
-- 404 page is requested. If the response isn't identical to the first 404 page, an error is returned. The reason is, 
-- obviously, because we now have no way to tell a valid page from an invalid one. 
--
--@param host The host object.
--@param port The port to which we are establishing the connection. 
--@return (status, result, body) If status is false, result is an error message. Otherwise, result is the code to expect and 
--        body is the cleaned-up body (or a hash of the cleaned-up body). 
local function identify_404(host, port)
	local data
	local bad_responses = { 301, 302, 401, 403, 499, 501 }

	data = http.get(host, port, URL_404)

	if(data == nil) then
		stdnse.print_debug(1, "http-enum.nse: Failed while testing for 404 status code")
		return false, "Failed while testing for 404 error message"
	end

	if(data.status and data.status == 404) then
		stdnse.print_debug(1, "http-enum.nse: Host returns proper 404 result.")
		return true, 404
	end

	if(data.status and data.status == 200) then
		stdnse.print_debug(1, "http-enum.nse: Host returns 200 instead of 404.")

		-- Clean up the body (for example, remove the URI). This makes it easier to validate later
		if(data.body) then
			-- Obtain another 404, with a different URI, to make sure things are consistent -- if they aren't, there's little hope
			local data2 = http.get(host, port, URL_404 .. "-2")
			if(data2 == nil) then
				stdnse.print_debug(1, "http-enum.nse: Failed while testing for second 404 error message")
				return false, "Failed while testing for second 404 error message"
			end

			-- Check if the return code became something other than 200
			if(data2.status ~= 200) then
				if(data2.status == nil) then
					data2.status = "<unknown>"
				end
				stdnse.print_debug(1, "http-enum.nse: HTTP 404 status changed during request (become %d; server is acting very strange).", data2.status)
				return false, string.format("HTTP 404 status changed during request (became %d; server is acting very strange).", data2.status)
			end

			-- Check if the returned body (once cleaned up) matches the first returned body
			local clean_body  = clean_404(data.body)
			local clean_body2 = clean_404(data2.body)
			if(clean_body ~= clean_body2) then
				stdnse.print_debug(1, "http-enum.nse: Two known 404 pages returned valid and different pages; unable to identify valid response.")
				stdnse.print_debug(1, "http-enum.nse: If you investigate the server and it's possible to clean up the pages, please post to nmap-dev mailing list.")
				return false, string.format("Two known 404 pages returned valid and different pages; unable to identify valid response.")
			end

			return true, 200, clean_body
		end

		stdnse.print_debug(1, "http-enum.nse: The 200 response didn't contain a body.")
		return true, 200
	end

	-- Loop through any expected error codes
	for _,code in pairs(bad_responses) do
		if(data.status and data.status == code) then
			stdnse.print_debug(1, "http-enum.nse: Host returns %s instead of 404 File Not Found.", get_status_string(data))
			return true, code
		end
	end

	stdnse.print_debug(1,  "Unexpected response returned for 404 check: %s", get_status_string(data))
--	io.write("\n\n" .. nsedebug.tostr(data) .. "\n\n")

	return false, string.format("Unexpected response returned for 404 check: %s", get_status_string(data))
end

---Determine whether or not the page that was returned is a 404 page. This is actually a pretty simple function, 
-- but it's best to keep this logic close to <code>identify_404</code>, since they will generally be used 
-- together. 
--
--@param data The data returned by the HTTP request
--@param result_404 The status code to expect for non-existent pages. This is returned by <code>identify_404</code>. 
--@param known_404  The 404 page itself, if <code>result_404</code> is 200. If <code>result_404</code> is something
--                  else, this parameter is ignored and can be set to <code>nil</code>. This is returned by 
--                  <code>identfy_404</code>. 
local function page_exists(data, result_404, known_404)
	if(data and data.status) then
		-- Handle the most complicated case first: the "200 Ok" response
		if(data.status == 200) then
			if(result_404 == 200) then
				-- If the 404 response is also "200", deal with it (check if the body matches)
				if(clean_404(data.body) ~= known_404) then
					stdnse.print_debug(1, "http-enum.nse: Page returned a body that doesn't match known 404 body, it exists")
					return true
				else
					return false
				end
			else
				-- If 404s return something other than 200, and we got a 200, we're good to go
				stdnse.print_debug(1, "http-enum.nse: Page was '%s', it exists!", get_status_string(data))
				return true
			end
		else
			-- If the result isn't a 200, check if it's a 404 or returns the same code as a 404 returned
			if(data.status ~= 404 and data.status ~= result_404) then
				-- If this check succeeded, then the page isn't a standard 404 -- it could be a redirect, authentication request, etc. Unless the user
				-- asks for everything (with a script argument), only display 401 Authentication Required here.
				stdnse.print_debug(1, "http-enum.nse: Page didn't match the 404 response (%s)", get_status_string(data))

				if(data.status == 401) then -- "Authentication Required"
					return true
				else
					if(nmap.registry.args.displayall == '1' or nmap.registry.args.displayall == "true") then
						return true
					end
				end

				return false
			else
				-- Page was a 404, or looked like a 404
				return false
			end
		end
	else
		stdnse.print_debug(1, "http-enum.nse: HTTP request failed (is the host still up?)")
		return false
	end
end

action = function(host, port)

	local response = " \n"

	-- Add URLs from external files
	local URLs = get_fingerprints()

	-- Check what response we get for a 404
	local result, result_404, known_404 = identify_404(host, port)
	if(result == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result_404
		else
			return nil
		end
	end

	-- Check if we can use HEAD requests
	local use_head = can_use_head(host, port, result_404)

	-- If we can't use HEAD, make sure we can use GET requests
	if(use_head == false) then
		local result, err = can_use_get(host, port)
		if(result == false) then
			if(nmap.debugging() > 0) then
				return "ERROR: " .. err
			else
				return nil
			end
		end
	end

	-- Queue up the checks
	local all = {}
	local i
	for i = 1, #URLs, 1 do
		if(nmap.registry.args.limit and i > tonumber(nmap.registry.args.limit)) then
			stdnse.print_debug(1, "http-enum.nse: Reached the limit (%d), stopping", nmap.registry.args.limit)
			break;
		end

		if(use_head) then
			all = http.pHead(host, port, URLs[i].checkdir, nil, nil, all)
		else
			all = http.pGet(host, port, URLs[i].checkdir, nil, nil, all)
		end
	end

	local results = http.pipeline(host, port, all, nil)

	-- Check for http.pipeline error
	if(results == nil) then
		stdnse.print_debug(1, "http-enum.nse: http.pipeline returned nil")
		if(nmap.debugging() > 0) then
			return "ERROR: http.pipeline returned nil"
		else
			return nil
		end
	end

	for i, data in pairs(results) do
		if(page_exists(data, result_404, known_404)) then
			if(URLs[i].checkdesc) then
				stdnse.print_debug(1, "http-enum.nse: Found a valid page! (%s: %s)", URLs[i].checkdir, URLs[i].checkdesc)
				response = response .. URLs[i].checkdir .. " " .. URLs[i].checkdesc .. "\n"
			else
				stdnse.print_debug(1, "http-enum.nse: Found a valid page! (%s: %s)", URLs[i].checkdir, URLs[i].checkdesc)
				response = response .. URLs[i].checkdir .. "\n"
			end
		end
	end
		
	if string.len(response) > 2 then
		return response
	end

	return nil
end
