description = [[
This script crawls through the website and returns any error pages.

The script will return all pages (sorted by error code) that respond with an
http code equal or above 400. To change this behaviour, please use the
<code>errcodes</code> option.

The script, by default, spiders and searches within forty pages. For large web
applications make sure to increase httpspider's <code>maxpagecount</code> value.
Please, note that the script will become more intrusive though.
]]

---
-- @usage nmap -p80 --script http-errors.nse <target>
--
-- @args http-errors.errcodes The error codes we are interested in.
--       Default: nil (all codes >= 400)
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-errors:
-- | Spidering limited to: maxpagecount=40; withinhost=some-random-page.com
-- |   Found the following error pages:
-- |
-- |   Error Code: 404
-- |       http://some-random-page.com/admin/
-- |
-- |   Error Code: 404
-- |       http://some-random-page.com/foo.html
-- |
-- |   Error Code: 500
-- |_      http://some-random-page.com/p.php
---

categories = {"discovery", "intrusive"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local httpspider = require "httpspider"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local function compare(a, b)
  return a[1] < b[1]
end

local function inTable(tbl, item)

  item = tostring(item)
  for key, value in pairs(tbl) do
    if value == tostring(item) then
      return true
    end
  end
  return nil

end

action = function(host, port)

  local errcodes = stdnse.get_script_args("http-errors.errcodes") or nil

  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME,
    maxpagecount = 40,
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

  crawler:set_timeout(10000)

  local errors = {}

  while (true) do

    local response, path

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

    if (response.status >= 400 and not errcodes) or
      ( errcodes and type(errcodes) == "table" and inTable(errcodes, response.status) ) then
      table.insert(errors, { tostring(response.status), path })
    end

  end

  -- If the table is empty.
  if next(errors) == nil then
    return "Couldn't find any error pages."
  end

  table.sort(errors, compare)

  -- Create a nice output.
  local results = {}
  for c, _ in pairs(errors) do
    table.insert(results, "\nError Code: " .. _[1])
    table.insert(results, "\t" .. _[2])
  end

  table.insert(results, 1, "Found the following error pages: ")

  results.name = crawler:getLimitations()

  return stdnse.format_output(true, results)

end
