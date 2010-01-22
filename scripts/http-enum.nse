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
-- |  |  /icons/: Icons and images
-- |  |  /images/: Icons and images
-- |  |  /robots.txt: Robots file
-- |  |  /sw/auth/login.aspx: Citrix WebTop
-- |  |  /images/outlook.jpg: Outlook Web Access
-- |  |  /nfservlets/servlet/SPSRouterServlet/: netForensics
-- |_ |_ /nfservlets/servlet/SPSRouterServlet/: netForensics
-- 
--
--@args displayall    Set to '1' or 'true' to display all status codes that may indicate a valid page, not just
--                    "200 OK" and "401 Authentication Required" pages. Although this is more likely to find certain
--                    hidden folders, it also generates far more false positives. 
--@args limit         Limit the number of folders to check. This option is useful if using a list from, for example, 
--                    the DirBuster projects which can have 80,000+ entries. 
--@args fingerprints  Specify a different file to read fingerprints from. This will be read instead of the default
--                    files. 
--@args path          The base path to prepend to each request. Leading/trailing slashes are not required. 
--@args variations    Set to '1' or 'true' to attempt variations on the files such as .bak, ~, Copy of", etc.

author = "Ron Bowes, Andrew Orr, Rob Nicholls"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}

require 'stdnse'
require 'http'
require 'stdnse'

-- List of fingerprint files
local fingerprint_files = { "http-fingerprints", "yokoso-fingerprints" }
if(nmap and nmap.registry and nmap.registry.args and nmap.registry.args.fingerprints ~= nil) then
	-- Specifying multiple entries in a table doesn't seem to work
	if(type(nmap.registry.args.fingerprints) == "table") then
		fingerprint_files = nmap.registry.args.fingerprints
	else
		fingerprint_files = { nmap.registry.args.fingerprints }
	end
end

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

---Convert the filename to backup variations. These can be valuable for a number of reasons. 
-- First, because they may not have the same access restrictions as the main version (file.php 
-- may run as a script, but file.php.bak or file.php~ might not). And second, the old versions
-- might contain old vulnerablities
--
-- At the time of the writing, these were all decided by me (Ron Bowes). 
local function get_variations(filename)
	local variations = {}

	if(filename == nil or filename == "" or filename == "/") then
		return {}
	end

	local is_directory = (string.sub(filename, #filename, #filename) == "/")
	if(is_directory) then
		filename = string.sub(filename, 1, #filename - 1)
	end

	-- Try some extensions
	table.insert(variations, filename .. ".bak")
	table.insert(variations, filename .. ".1")
	table.insert(variations, filename .. ".tmp")

	-- Strip off the extension, if it has one, and try it all again. 
	-- For now, just look for three-character extensions. 
	if(string.sub(filename, #filename - 3, #filename - 3) == '.') then
		local bare = string.sub(filename, 1, #filename - 4)
		local extension = string.sub(filename, #filename - 3)

		table.insert(variations, bare .. ".bak")
		table.insert(variations, bare .. ".1")
		table.insert(variations, bare .. ".tmp")
		table.insert(variations, bare .. "_1" .. extension)
		table.insert(variations, bare .. "2" .. extension)
	end

	-- Some compressed formats
	table.insert(variations, filename .. ".zip")
	table.insert(variations, filename .. ".tar")
	table.insert(variations, filename .. ".tar.gz")
	table.insert(variations, filename .. ".tgz")
	table.insert(variations, filename .. ".tar.bz2")


	-- Some Windowsy things
	local onlyname = string.sub(filename, 2)
	-- If the name contains a '/', forget it
	if(string.find(onlyname, "/") == nil) then
		table.insert(variations, "/Copy of " .. onlyname)
		table.insert(variations, "/Copy (2) of " .. onlyname)
		table.insert(variations, "/Copy of Copy of " .. onlyname)

		-- Word/Excel/etc replace the first two characters with '~$', it seems
		table.insert(variations, "/~$" .. string.sub(filename, 4))
	end

	-- Some editors add a '~'
	table.insert(variations, filename .. "~")

	-- Try some directories
	table.insert(variations, "/bak" .. filename)
	table.insert(variations, "/backup" .. filename)
	table.insert(variations, "/backups" .. filename)
	table.insert(variations, "/beta" .. filename)
	table.insert(variations, "/test" .. filename)

	-- If it's a directory, add a '/' after every entry
	if(is_directory) then
		for i, v in ipairs(variations) do
			variations[i] = v .. "/"
		end
	end

	return variations
end

---Get the list of fingerprints from files. The files are defined in <code>fingerprint_files</code>. 
--
--@return An array of entries, each of which have a <code>checkdir</code> field, and possibly a <code>checkdesc</code>. 
local function get_fingerprints()
	local entries  = {}
	local PREAUTH  = "# Pre-Auth"
	local POSTAUTH = "# Post-Auth"

	local i

	-- Check if we've already read the file
	-- There might be a race condition here, where multiple scripts will read the file and set this variable, but the impact
	-- of that would be minimal (and definitely isn't security)
	if(nmap.registry.http_fingerprints ~= nil) then
		stdnse.print_debug(1, "http-enum: Using cached HTTP fingerprints")
		return nmap.registry.http_fingerprints
	end

	for i = 1, #fingerprint_files, 1 do
		local count = 0

		-- Try using the root path, if possible
		local filename = fingerprint_files[i]
		local filename_full = nmap.fetchfile(filename)

		if(filename_full == nil) then
			-- If the root path fails, try looking in the nselib/data directory
			filename = "nselib/data/" .. fingerprint_files[i]
			filename_full = nmap.fetchfile(filename)
		end
	
		if(filename_full == nil) then
			stdnse.print_debug(1, "http-enum: Couldn't find fingerprints file: %s", filename)
		else
			stdnse.print_debug(1, "http-enum: Attempting to parse fingerprint file %s", filename)

			local product = nil
			for line in io.lines(filename_full) do
				-- Ignore "Pre-Auth", "Post-Auth", and blank lines
				if(string.sub(line, 1, #PREAUTH) ~= PREAUTH and string.sub(line, 1, #POSTAUTH) ~= POSTAUTH and #line > 0) then
					-- Commented lines indicate products
					if(string.sub(line, 1, 1) == "#") then
						product = string.sub(line, 3)
					else
						table.insert(entries, {checkdir=line, checkdesc=product})
						count = count + 1

						-- If the user requested variations, add those as well
						if(nmap.registry.args.variations == '1' or nmap.registry.args.variations == 'true') then
							local variations = get_variations(line)
							for _, variation in ipairs(variations) do
								table.insert(entries, {checkdir=variation, checkdesc=product .. " (variation)"})
							end
						end
					end
				end
			end
		
			stdnse.print_debug(1, "http-enum: Added %d entries from file %s", count, filename)
		end
	end

	-- Cache the fingerprints for other scripts, so we aren't reading the files every time
	nmap.registry.http_fingerprints = entries
	
	return entries
end

action = function(host, port)

	local response = {}

	-- Add URLs from external files
	local URLs = get_fingerprints()

	-- Check what response we get for a 404
	local result, result_404, known_404 = http.identify_404(host, port)
	if(result == false) then
		return stdnse.format_output(false, result_404)
	end

	-- Check if we can use HEAD requests
	local use_head = http.can_use_head(host, port, result_404)

	-- If we can't use HEAD, make sure we can use GET requests
	if(use_head == false) then
		local result, err = http.can_use_get(host, port)
		if(result == false) then
			return stdnse.format_output(false, err)
		end
	end

	-- Get the base path, if the user entered one
	local paths = {''}
	if(nmap.registry.args.path ~= nil) then
		if(type(nmap.registry.args.path) == 'table') then
			paths = nmap.registry.args.path
		else
			paths = { nmap.registry.args.path }
		end
	end

	-- Queue up the checks

	for j = 1, #paths, 1 do
		local all = {}
		local path = paths[j]

		-- Remove trailing slash, if it exists
		if(#path > 1 and string.sub(path, #path, #path) == '/') then
			path = string.sub(path, 1, #path - 1)
		end

		-- Add a leading slash, if it doesn't exist
		if(#path <= 1) then
			path = ''
		else
			if(string.sub(path, 1, 1) ~= '/') then
				path = '/' .. path
			end
		end

		-- Loop through the URLs
		stdnse.print_debug(1, "http-enum.nse: Searching for entries under path '%s' (change with 'path' argument)", path)
		for i = 1, #URLs, 1 do
			if(nmap.registry.args.limit and i > tonumber(nmap.registry.args.limit)) then
				stdnse.print_debug(1, "http-enum.nse: Reached the limit (%d), stopping", nmap.registry.args.limit)
				break;
			end

			if(use_head) then
				all = http.pHead(host, port, path .. URLs[i].checkdir, nil, nil, all)
			else
				all = http.pGet(host, port, path .. URLs[i].checkdir, nil, nil, all)
			end
		end

		local results = http.pipeline(host, port, all, nil)
	
		-- Check for http.pipeline error
		if(results == nil) then
			stdnse.print_debug(1, "http-enum.nse: http.pipeline returned nil")
			return stdnse.format_output(false, "http.pipeline returned nil")
		end
	
		for i, data in pairs(results) do
			if(http.page_exists(data, result_404, known_404, path .. URLs[i].checkdir, nmap.registry.args.displayall)) then
				-- Build the description
				local description = string.format("%s", path .. URLs[i].checkdir)
				if(URLs[i].checkdesc) then
					description = string.format("%s: %s", path .. URLs[i].checkdir, URLs[i].checkdesc)
				end
	
				-- Build the status code, if it isn't a 200
				local status = ""
				if(data.status ~= 200) then
					status = " (" .. http.get_status_string(data) .. ")"
				end
	
				stdnse.print_debug("Found a valid page! (%s)%s", description, status)

				table.insert(response, string.format("%s%s", description, status))	
			end
		end
	end
		
	return stdnse.format_output(true, response)
end
