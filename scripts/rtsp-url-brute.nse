local coroutine = require "coroutine"
local io = require "io"
local nmap = require "nmap"
local rtsp = require "rtsp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.
]]

---
-- @usage
-- nmap --script rtsp-url-brute -p 554 <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 554/tcp open  rtsp
-- | rtsp-url-brute: 
-- |   Discovered URLs
-- |_    rtsp://camera.example.com/mpeg4
--
-- The script attempts to discover valid RTSP URLs by sending a DESCRIBE
-- request for each URL in the dictionary. It then parses the response, based
-- on which it determines whether the URL is valid or not.
--
-- @args rtsp-url-brute.urlfile sets an alternate URL dictionary file
-- @args rtsp-url-brute.threads sets the maximum number of parallell threads to run

--
-- Version 0.1
-- Created 23/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


portrule = shortport.port_or_service(554, "rtsp", "tcp", "open")

--- Retrieves the next RTSP relative URL from the datafile
-- @param filename string containing the name of the file to read from
-- @return url string containing the relative RTSP url
urlIterator = function(fd)
	local function getNextUrl ()
		repeat
			local line = fd:read()
			if ( line and not(line:match('^#!comment:')) ) then
				coroutine.yield(line)
			end
		until(not(line))
		fd:close()
		while(true) do coroutine.yield(nil) end
	end
	return coroutine.wrap( getNextUrl )
end

-- Fetches the next url from the iterator, creates an absolute url and tries
-- to fetch it from the RTSP service.
-- @param host table containing the host table as received by action 
-- @param port table containing the port table as received by action 
-- @param url_iter function containing the url iterator
-- @param result table containing the urls that were successfully retrieved
local function processURL(host, port, url_iter, result)
	local condvar = nmap.condvar(result)
	for u in url_iter do
		local name = ( host.targetname and #host.targetname > 0 ) and host.targetname or
		 			 ( host.name and #host.name > 0 ) and host.name or 
					   host.ip
		local url = ("rtsp://%s%s"):format(name, u)
		local helper = rtsp.Helper:new(host, port)
		local status = helper:connect()

		if ( not(status) ) then
			stdnse.print_debug(2, "ERROR: Connecting to RTSP server url: %s", url)
			table.insert(result, { url = url, status = -1 } )
			break
		end

    local response
		status, response = helper:describe(url)
		if ( not(status) ) then
			stdnse.print_debug(2, "ERROR: Sending DESCRIBE request to url: %s", url)
			table.insert(result, { url = url, status = -1 } )
			break
		end

		table.insert(result, { url = url, status = response.status } )
		helper:close()
	end		
	condvar "signal"
end

action = function(host, port)

	local response
	local result = {}
	local condvar = nmap.condvar(result)
	local threadcount = stdnse.get_script_args('rtsp-url-brute.threads') or 10
	local filename = stdnse.get_script_args('rtsp-url-brute.urlfile') or
	                 nmap.fetchfile("nselib/data/rtsp-urls.txt")
	
	threadcount = tonumber(threadcount)

	if ( not(filename) ) then
		return stdnse.format_output(false, "No dictionary could be loaded")
	end

	local f = io.open(filename)
	if ( not(f) ) then
		return stdnse.format_output(false, ("Failed to open dictionary file: %s"):format(filename))
	end
	
	local url_iter = urlIterator(f)
	if ( not(url_iter) ) then
		return stdnse.format_output(false, ("Could not open the URL dictionary: "):format(f))
	end
	
	local threads = {}
	for t=1, threadcount do
		local co = stdnse.new_thread(processURL, host, port, url_iter, result)
		threads[co] = true
	end

	repeat
		for t in pairs(threads) do
			if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
		end
		if ( next(threads) ) then
			condvar "wait"
		end
	until( next(threads) == nil )

	-- urls that could not be retrieved due to low level errors, such as
	-- failure in socket send or receive
	local failure_urls = { name='An error occured while testing the following URLs' }

	-- urls that illicited a 200 OK response 
	local success_urls = { name='Discovered URLs' }
	
	-- urls requiring authentication
	-- local auth_urls = { name='URL requiring authentication' }
	
	for _, r in ipairs(result) do
		if ( r.status == -1 ) then
			table.insert(failure_urls, r.url)
		elseif ( r.status == 200 ) then
			table.insert(success_urls, r.url)
--		elseif ( r.status == 401 ) then
--			table.insert(auth_urls, r.url )
		end
	end

	local result = { success_urls, failure_urls }

--	-- insert our URLs requiring auth ONLY if not ALL urls returned auth
--	if (#result > #auth_urls) then
--		table.insert(result, 2, auth_urls)
--	end
	
	return stdnse.format_output(true, result )
end
