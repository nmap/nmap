local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Spiders a website and attempts to identify open redirects. Open
redirects are handlers which commonly take a URL as a parameter and
responds with a http redirect (3XX) to the target.  Risks of open redirects are described at http://cwe.mitre.org/data/definitions/601.html.
]]

---
-- @usage
-- nmap --script=http-open-redirect <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-open-redirect: 
-- |_  https://foobar.target.se:443/redirect.php?url=http%3A%2f%2fscanme.nmap.org%2f
--
-- @args http-open-redirect.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-open-redirect.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-open-redirect.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-open-redirect.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-open-redirect.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Martin Holst Swende"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

local function dbg(str,...)
	stdnse.print_debug(2,"http-open-redirect:"..str, ...)
end
local function dbgt(tbl)
	for k,v in pairs(tbl) do
		dbg(" %s = %s " , tostring(k), tostring(v))
	end
end

local function getHostPort(parsed)
	local host, port = parsed.host, parsed.port
	-- if no port was found, try to deduce it from the scheme
	if ( not(port) ) then
		port = (parsed.scheme == 'https') and 443
		port = port or ((parsed.scheme == 'http') and 80)
	end
	return host, port
end

local function isRedirect(status)
	return status >= 300 and status <=399
end


-- This function checks if any query parameter was used as a forward destination
-- @return false or a new query string to test
local function checkLocationEcho(query, destination)
	dbg("checkLocationEcho(%s, %s)", tostring(query), tostring(destination))
	local q = url.parse_query(query);
	-- Check the values (and keys) and see if they are reflected in the location header
	for k,v in pairs(q) do
		local s,f = string.find(destination, v)
		if s == 1 then 
			-- Build a new URL
			q[k] = "http%3A%2f%2fscanme.nmap.org%2f";
			return url.build_query(q)
		end
	end
	return false;
end


action = function(host, port)

	local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME, redirect_ok = false } )
	crawler:set_timeout(10000)
	
	local results = {}
	while(true) do
		local status, r = crawler:crawl()
		-- if the crawler fails it can be due to a number of different reasons
		-- most of them are "legitimate" and should not be reason to abort
		if ( not(status) ) then
			if ( r.err ) then
				return stdnse.format_output(true, "ERROR: %s", r.reason)
			else
				break
			end
		end
		local response = r.response
		-- Was it a redirect?		
		if response and response.header and response.header.location and isRedirect(response.status)  then
			-- Were any parameters involved?
			local parsed = url.parse(tostring(r.url));
			
			-- We are only interested in links which have parameters
			if parsed.query and #parsed.query > 0 then
				-- Now we need to check if any of the parameters were echoed in the location-header
				local destination = response.header.location
				local newQuery = checkLocationEcho(parsed.query, destination)
				--dbg("newQuery: %s" , tostring(newQuery))
				if newQuery then
					local host, port = getHostPort(parsed);
					local ppath = url.parse_path(parsed.path or "")
					local url = url.build_path(ppath)
					if parsed.params then url = url .. ";" .. parsed.params end
					url = url .. "?" .. newQuery
					dbg("Checking potential open redirect: %s:%s%s", host,port,url);
					local testResponse = http.get(host, port, url);
					--dbgt(testResponse)
					if isRedirect(testResponse.status) and testResponse.header.location == "http://scanme.nmap.org/" then
						table.insert(results, ("%s://%s:%s%s"):format(parsed.scheme, host, port,url))
					end
				end
			end
		end

	end
	if ( #results> 0 ) then
		return stdnse.format_output(true, results)
	end
end
