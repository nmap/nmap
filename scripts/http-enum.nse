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
--@args limit      Limit the number of folders to check. This option is useful if using a list from, for example, 
--                 the DirBuster projects which can have 80,000+ entries. 

author = "Ron Bowes <ron@skullsecurity.net>, Andrew Orr <andrew@andreworr.ca>, Rob Nicholls <robert@everythingeverything.co.uk>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}

require 'stdnse'
require 'http'
require 'stdnse'

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

action = function(host, port)

	local response = " \n"

	-- Add URLs from external files
	local URLs = get_fingerprints()

	-- Check what response we get for a 404
	local result, result_404, known_404 = http.identify_404(host, port)
	if(result == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result_404
		else
			return nil
		end
	end

	-- Check if we can use HEAD requests
	local use_head = http.can_use_head(host, port, result_404)

	-- If we can't use HEAD, make sure we can use GET requests
	if(use_head == false) then
		local result, err = http.can_use_get(host, port)
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
		if(http.page_exists(data, result_404, known_404, URLs[i].checkdir)) then
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
