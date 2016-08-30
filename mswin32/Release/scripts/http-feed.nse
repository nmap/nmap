description = [[
This script crawls through the website to find any rss or atom feeds.

The script, by default, spiders and searches within forty pages. For large web
applications make sure to increase httpspider's <code>maxpagecount</code> value.
Please, note that the script will become more intrusive though.
]]

---
-- @usage nmap -p80 --script http-feed.nse <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-feed:
-- | Spidering limited to: maxpagecount=40; withinhost=some-random-page.com
-- |   Found the following feeds:
-- |     RSS (version 2.0): http://www.some-random-page.com/2011/11/20/feed/
-- |     RSS (version 2.0): http://www.some-random-page.com/2011/12/04/feed/
-- |     RSS (version 2.0): http://www.some-random-page.com/category/animalsfeed/
-- |     RSS (version 2.0): http://www.some-random-page.com/comments/feed/
-- |_    RSS (version 2.0): http://www.some-random-page.com/feed/
---

categories = {"discovery", "intrusive"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

FEEDS = { RSS = { search = { '<rss(.*)>' }, version = 'version=["\'](.-)["\']' },
          Atom = { search = { '<feed(.*)>' }, version = 'version=["\'](.-)["\']' },
        }

FEEDS_REFS = { "type=[\"']application/rss%+xml[\"']%s*href=[\"'](.-)[\"']",
        "type=[\"']application/rss%+xml[\"']%s*title=[\"'].-[\"']%s*href=[\"'](.-)[\"']",
        "type=[\"']application/atom%+xml[\"']%s*href=[\"'](.-)[\"']",
        "type=[\"']application/atom%+xml[\"']%s*title=[\"'].-[\"']%s*href=[\"'](.-)[\"']",
      }

feedsfound = {}

checked = {}

-- Searches the resource for feeds.
local findFeeds = function(body, path)

  if body then
    for _, f in pairs(FEEDS) do
      for __, pf in pairs(f["search"]) do

        local c = string.match(body, pf)

        if c then
          local v = ""
          -- Try to find feed's version.
          if string.match(c, f["version"]) then
            v = " (version " .. string.match(c, f["version"]) .. ")"
          end
          feedsfound[path] =  _ .. v .. ": "
        end

      end
    end
  end
  checked[path] = true
end


action = function(host, port)

  --TODO: prefix this with SCRIPT_NAME and document it.
  local maxpagecount = stdnse.get_script_args("maxpagecount") or 40

  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME,
    maxpagecount = maxpagecount,
    maxdepth = -1,
    withinhost = 1
  })

  crawler.options.doscraping = function(url)
    if crawler:iswithinhost(url)
      and not crawler:isresource(url, "js")
      and not crawler:isresource(url, "css") then
      return true
    end
  end

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  local index, k, target, response, path
  while (true) do

    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    response = r.response
    path = tostring(r.url)

    if response.body then
      findFeeds(response.body, path)

      for _, p in ipairs(FEEDS_REFS) do
        for l in string.gmatch(response.body, p) do
          if not checked[l] then
            local resp
            -- If this is an absolute URL, use get_url.
            if string.match(l, "^http") then
              resp = http.get_url(l)
            else
              resp = http.get(host, port, l)
            end
            if resp.body then
              findFeeds(resp.body, l)
            end
          end
        end
      end
    end

  end

  -- If the table is empty.
  if next(feedsfound) == nil then
    return "Couldn't find any feeds."
  end

  -- Create a nice output.
  local results = {}
  for c, _ in pairs(feedsfound) do
    table.insert(results, {_ .. c } )
  end

  table.insert(results, 1, "Found the following feeds: ")

  results.name = crawler:getLimitations()

  return stdnse.format_output(true, results)

end
