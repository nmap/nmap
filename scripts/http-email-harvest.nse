description = [[
Spiders a web site and collects e-mail addresses
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
categories = {"discovery", "safe"}

require "httpspider"
require "shortport"

portrule = shortport.http

function action(host, port)
	local EMAIL_PATTERN = "[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?"
	
	local crawler = httpspider.Crawler:new(host, port, url or '/', { 
			scriptname = SCRIPT_NAME
		}
	)

	crawler:set_timeout(10000)

	local maxdepth, maxpagecount = crawler.options.maxdepth, crawler.options.maxpagecount
	if ( maxdepth < 0 ) then maxdepth = nil end
	if ( maxpagecount < 0 ) then maxpagecount = nil end
	
	stdnse.print_debug(2, "%s: Running crawler maxdepth: %s; maxpagecount: %s", 
		SCRIPT_NAME, maxdepth or "[none]", maxpagecount or "[none]")

	local emails = {}
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
		
		-- Collect each e-mail address and build a unique index of them
   		for email in r.response.body:gmatch(EMAIL_PATTERN) do
      		emails[email] = true
		end
	end

	-- if no email addresses were collected abort
	if ( not(emails) ) then	return end

	local results = {}
	for email, _ in pairs(emails) do
		table.insert(results, email)
  	end

	-- Inform the user of the limitations that were used
	if ( maxdepth > 0 or maxpagecount > 0 ) then
		local limit = "Spidering limited to: "
		if ( maxdepth > 0 ) then
			limit = limit .. ("maxdepth=%d; "):format(maxdepth)
		end
		if ( maxpagecount > 0 ) then
			limit = limit .. ("maxpagecount=%d"):format(maxpagecount)
		end
		if ( #results == 0 ) then
			table.insert(results, limit)
		else
			results.name = limit
		end
	end
	return stdnse.format_output(true, results)
end
