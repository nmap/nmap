local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Spiders a web site and collects e-mail addresses.
]]

---
-- @usage
-- nmap --script=http-email-harvest <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-email-harvest: 
-- | Spidering limited to: maxdepth=3; maxpagecount=20
-- |   root@examplec.com
-- |_  postmaster@example.com
--
-- @args http-email-harvest.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-email-harvest.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-email-harvest.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-email-harvest.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-email-harvest.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

function action(host, port)
	local EMAIL_PATTERN = "[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?"
	
	local crawler = httpspider.Crawler:new(host, port, nil, { 
			scriptname = SCRIPT_NAME
		}
	)

	if ( not(crawler) ) then
		return
	end
	crawler:set_timeout(10000)

	local emails = {}
	while(true) do
		local status, r = crawler:crawl()
		-- if the crawler fails it can be due to a number of different reasons
		-- most of them are "legitimate" and should not be reason to abort
		if ( not(status) ) then
			if ( r.err ) then
				return stdnse.format_output(true, ("ERROR: %s"):format(r.reason))
			else
				break
			end
		end
		
		-- Collect each e-mail address and build a unique index of them
    if r.response.body then
      for email in r.response.body:gmatch(EMAIL_PATTERN) do
        emails[email] = true
      end
    end
	end

	-- if no email addresses were collected abort
	if ( not(emails) ) then	return end

	local results = {}
	for email, _ in pairs(emails) do
		table.insert(results, email)
  	end

	results.name = crawler:getLimitations()
	
	return stdnse.format_output(true, results)
end
