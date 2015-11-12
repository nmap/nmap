local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

description = [[
Spiders a website and attempts to identify output escaping problems
where content is reflected back to the user.  This script locates all
parameters, ?x=foo&y=bar and checks if the values are reflected on the
page. If they are indeed reflected, the script will try to insert
ghz>hzx"zxc'xcv and check which (if any) characters were reflected
back onto the page without proper html escaping.  This is an
indication of potential XSS vulnerability.
]]

---
-- @usage
-- nmap --script=http-unsafe-output-escaping <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- | http-unsafe-output-escaping:
-- |   Characters [> " '] reflected in parameter kalle at http://foobar.gazonk.se/xss.php?foo=bar&kalle=john
-- |_  Characters [> " '] reflected in parameter foo at http://foobar.gazonk.se/xss.php?foo=bar&kalle=john
--
-- @args http-unsafe-output-escaping.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-unsafe-output-escaping.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-unsafe-output-escaping.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-unsafe-output-escaping.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-unsafe-output-escaping.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Martin Holst Swende"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

local dbg = stdnse.debug2

local function getHostPort(parsed)
  local host, port = parsed.host, parsed.port
  -- if no port was found, try to deduce it from the scheme
  if ( not(port) ) then
    port = (parsed.scheme == 'https') and 443
    port = port or ((parsed.scheme == 'http') and 80)
  end
  return host, port
end
local function getReflected(parsed, r)
  local reflected_values,not_reflected_values = {},{}
  local count = 0
  -- Now, we need to check the parameters and keys
  local q = url.parse_query(parsed.query)
  -- Check the values (and keys) and see if they are reflected in the page
  for k,v in pairs(q) do
    if r.response.body and r.response.body:find(v, 1, true) then
      dbg("Reflected content %s=%s", k,v)
      reflected_values[k] = v
      count = count +1
    else
      not_reflected_values[k] = v
    end
  end
  if count > 0 then
    return reflected_values,not_reflected_values,q
  end
end

local function addPayload(v)
  return v.."ghz>hzx\"zxc'xcv"
end

local function createMinedLinks(reflected_values, all_values)
  local new_links = {}
  for k,v in pairs(reflected_values) do
    -- First  of all, add the payload to the reflected param
    local urlParams = { [k] = addPayload(v)}
    for k2,v2 in pairs(all_values) do
      if k2 ~= k then
        urlParams[k2] = v2
      end
    end
    new_links[k] = url.build_query(urlParams)
  end
  return new_links
end

local function locatePayloads(response)
  local results = {}
  if response.body:find("ghz>hzx") then table.insert(results,">") end
  if response.body:find('hzx"zxc') then table.insert(results,'"')  end
  if response.body:find("zxc'xcv") then table.insert(results,"'")  end
  return #results > 0 and results
end

local function visitLinks(host, port,parsed,new_links, results,original_url)
  for k,query in pairs(new_links) do
    local ppath = url.parse_path(parsed.path or "")
    local url = url.build_path(ppath)
    if parsed.params then url = url .. ";" .. parsed.params end
    url = url .. "?" .. query
    dbg("Url to visit: %s", url)
    local response = http.get(host, port, url)
    local result = locatePayloads(response)
    if result then
      table.insert(results, ("Characters [%s] reflected in parameter %s at %s"):format(table.concat(result," "),k, original_url))
    end
  end
end

action = function(host, port)

  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
  crawler:set_timeout(10000)

  local results = {}
  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- parse the returned url
    local parsed = url.parse(tostring(r.url))
    -- We are only interested in links which have parameters
    if parsed.query and #parsed.query > 0 then
      local host, port = getHostPort(parsed)
      local reflected_values,not_reflected_values,all_values = getReflected(parsed, r)


      -- Now,were any reflected ?
      if  reflected_values then
        -- Ok, create new links with payloads in the reflected slots
        local new_links = createMinedLinks(reflected_values, all_values)

        -- Now, if we had 2 reflected values, we should have 2 new links to fetch
        visitLinks(host, port,parsed, new_links, results,tostring(r.url))
      end
    end
  end
  if ( #results> 0 ) then
    return stdnse.format_output(true, results)
  end
end
