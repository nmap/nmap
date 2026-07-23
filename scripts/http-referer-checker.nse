description = [[
Informs about cross-domain include of scripts. Websites that include
external javascript scripts are delegating part of their security to
third-party entities.
]]

---
-- @usage nmap -p80 --script http-referer-checker.nse <host>
--
-- This script informs about cross-domain include of scripts by
-- finding src attributes that point to a different domain.
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-referer-checker:
-- | Spidering limited to: maxdepth=3; maxpagecount=20;
-- |   http://css3-mediaqueries-js.googlecode.com/svn/trunk/css3-mediaqueries.js
-- |_  http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js?ver=3.4.2
--
---

categories = {"discovery", "safe"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local httpspider = require "httpspider"

portrule = shortport.http

action = function(host, port)

  local scripts = {}

  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME,
    maxpagecount = 30,
    maxdepth = -1,
    withinhost = true
  })
  if not crawler then
    return
  end

  crawler.options.withinhost = function(url)
    -- Check for cross-domain javascript
    if not crawler:iswithindomain(url) and crawler:isresource(url, "js") then
      scripts[tostring(url)] = true
    end
    -- But don't actually fetch it if it's not on the same host
    return crawler:iswithinhost(url)
  end

  crawler.options.doscraping = function(url)
    return (not crawler:isresource(url, "js")
      and not crawler:isresource(url, "css"))
  end

  crawler:set_timeout(10000)

  while(true) do

    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

  end

  if next(scripts) == nil then
    return "Couldn't find any cross-domain scripts."
  end

  local results = {}
  for s, _ in pairs(scripts) do
    table.insert(results, s)
  end

  results.name = crawler:getLimitations()

  return stdnse.format_output(true, results)

end
