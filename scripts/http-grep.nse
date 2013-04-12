local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Spiders a website and attempts to match all pages and urls against a given
string. Matches are counted and grouped per url under which they were
discovered.
]]

---
-- @usage
-- nmap -p 80 www.example.com --script http-grep --script-args='http-grep.match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",http-grep.breakonmatch'
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-grep: 
-- |   (4) http://example.com/name/
-- |     + name@example.com
-- |     + name@example.com
-- |     + name@example.com
-- |     + name@example.com
-- |   (4) http://example.com/sales.html
-- |     + sales@example.com
-- |     + sales@example.com
-- |     + sales@example.com
-- |__   + sales@example.com
--
-- @args http-grep.match the string to match in urls and page contents
-- @args http-grep.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-grep.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-grep.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-grep.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-grep.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

-- Shortens a matching string if it exceeds 60 characters
-- All characters after 60 will be replaced with ...
local function shortenMatch(match)
	if ( #match > 60 ) then
		return match:sub(1, 60) .. " ..."
	else
		return match
	end
end

action = function(host, port)

	-- read script specific arguments
	local match 			= stdnse.get_script_args("http-grep.match")
	local break_on_match 	= stdnse.get_script_args("http-grep.breakonmatch")
	
	if ( not(match) ) then
		return stdnse.format_output(true, "ERROR: Argument http-grep.match was not set")
	end
	
	local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
	local results = {}

	-- set timeout to 10 seconds
	crawler:set_timeout(10000)
	
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

		local matches = {}
		local body = r.response.body
		-- try to match the url and body
		if body and ( body:match( match ) or tostring(r.url):match(match) ) then
			local count = select(2, body:gsub(match, match))
			for match in body:gmatch(match) do
				table.insert(matches, "+ " .. shortenMatch(match))
			end
			
			matches.name = ("(%d) %s"):format(count,tostring(r.url))
			table.insert(results, matches)
			
			-- should we continue to search for matches?
			if ( break_on_match ) then
				crawler:stop()
				break
			end
		end
	end
	table.sort(results, function(a,b) return a.name>b.name end)
	return stdnse.format_output(true, results)	
end
