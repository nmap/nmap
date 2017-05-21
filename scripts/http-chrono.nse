local http = require "http"
local httpspider = require "httpspider"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local url = require "url"

description = [[
Measures the time a website takes to deliver a web page and returns
the maximum, minimum and average time it took to fetch a page.

Web pages that take longer time to load could be abused by attackers in DoS or
DDoS attacks due to the fact that they are likely to consume more resources on
the target server. This script could help identifying these web pages.
]]

---
-- @usage
-- nmap --script http-chrono <ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-chrono: Request times for /; avg: 2.98ms; min: 2.63ms; max: 3.62ms
--
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-chrono:
-- | page                         avg      min      max
-- | /admin/                      1.91ms   1.65ms   2.05ms
-- | /manager/status              2.14ms   2.03ms   2.24ms
-- | /manager/html                2.26ms   2.09ms   2.53ms
-- | /examples/servlets/          2.43ms   1.97ms   3.62ms
-- | /examples/jsp/snp/snoop.jsp  2.75ms   2.59ms   3.13ms
-- | /                            2.78ms   2.54ms   3.36ms
-- | /docs/                       3.14ms   2.61ms   3.53ms
-- | /RELEASE-NOTES.txt           3.70ms   2.97ms   5.58ms
-- | /examples/jsp/               4.93ms   3.39ms   8.30ms
-- |_/docs/changelog.html         10.76ms  10.14ms  11.46ms
--
-- @args http-chrono.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-chrono.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 1)
-- @args http-chrono.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-chrono.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-chrono.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
-- @args http-chrono.tries the number of times to fetch a page based on which
--       max, min and average calculations are performed.


author = "Ange Gutek"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

action = function(host, port)

  local maxpages = stdnse.get_script_args(SCRIPT_NAME .. ".maxpagecount") or 1
  local tries = stdnse.get_script_args(SCRIPT_NAME .. ".tries") or 5

  local dump = {}
  local crawler = httpspider.Crawler:new( host, port, nil, { scriptname = SCRIPT_NAME, maxpagecount = tonumber(maxpages) } )
  crawler:set_timeout(10000)

  -- launch the crawler
  while(true) do
    local start = stdnse.clock_ms()
    local status, r = crawler:crawl()
    if ( not(status) ) then
      break
    end
    local chrono = stdnse.clock_ms() - start
    dump[chrono] = tostring(r.url)
  end

  -- retest each page x times to find an average speed
  -- a significant diff between instant and average may be an evidence of some weakness
  -- either on the webserver or its database
  local average,count,page_test
  local results = {}
  for result, page in pairs (dump) do
    local url_host, url_page = page:match("//(.-)/(.*)")
    url_host = string.gsub(url_host,":%d*","")

    local min, max, page_test
    local bulk_start = stdnse.clock_ms()
    for i = 1,tries do
      local start = stdnse.clock_ms()
      if ( url_page:match("%?") ) then
        page_test = http.get(url_host,port,"/"..url_page.."&test="..math.random(100), { no_cache = true })
      else
        page_test = http.get(url_host,port,"/"..url_page.."?test="..math.random(100), { no_cache = true })
      end
      local count = stdnse.clock_ms() - start
      if ( not(max) or max < count ) then
        max = count
      end
      if ( not(min) or min > count ) then
        min = count
      end
    end

    local count = stdnse.clock_ms() - bulk_start
    table.insert(results, { min = min, max = max, avg = (count / tries), page = url.parse(page).path })
  end

  local output
  if ( #results > 1 ) then
    table.sort(results, function(a, b) return a.avg < b.avg end)
    output = tab.new(4)
    tab.addrow(output, "page", "avg", "min", "max")
    for _, entry in ipairs(results) do
      tab.addrow(output, entry.page, ("%.2fms"):format(entry.avg), ("%.2fms"):format(entry.min), ("%.2fms"):format(entry.max))
    end
    output = "\n" .. tab.dump(output)
  else
    local entry = results[1]
    output = ("Request times for %s; avg: %.2fms; min: %.2fms; max: %.2fms"):format(entry.page, entry.avg, entry.min, entry.max)
  end
  return output
end




