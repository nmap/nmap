description = [[
Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL
injection attack.

The script spiders an HTTP server looking for URLs containing queries. It then
proceeds to combine crafted SQL commands with susceptible URLs in order to
obtain errors. The errors are analysed to see if the URL is vulnerable to
attack. This uses the most basic form of SQL injection but anything more
complicated is better suited to a standalone tool. 

We may not have access to the target web server's true hostname, which can prevent access to
virtually hosted sites.
]]

require('url')
require('shortport')
require('stdnse')
require('strbuf')
require('comm')
require('http')
require('nsedebug')
require('httpspider')

author = "Eddie Bell"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

---
-- @args sql-injection.start The path at which to start spidering; default <code>/</code>.
-- @args sql-injection.maxdepth The maximum depth to spider; default 10.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | sql-injection: Host might be vulnerable
-- | /a_index.php?id_str=1'%20OR%20sqlspider
-- | /a_index.php?id_str=1'%20OR%20sqlspider
-- | /a_index.php?id_str=2'%20OR%20sqlspider

-- default settings
local maxdepth = 10
local start = '/'

portrule = shortport.port_or_service({80, 443}, {"http","https"})

--[[
Pattern match response from a submitted injection query to see
if it is vulnerable
--]]

local function check_injection_response(response)

  local body = string.lower(response.body)

  if not (response.status == 200 or response.status ~= 500) then
    return false 
  end

  return (string.find(body, "invalid query") or
	  string.find(body, "sql syntax") or
	  string.find(body, "odbc drivers error"))
end

--[[
Replaces usual queries with malicious querie and return a table with them.
]]--

local function build_injection_vector(urls)
  local utab, k, v, urlstr, response
  local qtab, old_qtab, results
  local all = {}

  for _, injectable in ipairs(urls) do
    if type(injectable) == "string"  then
      utab = url.parse(injectable)
      qtab = url.parse_query(utab.query)

      for k, v in pairs(qtab) do
        old_qtab = qtab[k];
        qtab[k] = qtab[k] ..  "'%20OR%20sqlspider"
          
        utab.query = url.build_query(qtab)
        urlstr = url.build(utab)
        table.insert(all, urlstr)

	qtab[k] = old_qtab
	utab.query = url.build_query(qtab)
      end
    end
  end
  return all 
end

--[[
Creates a pipeline table and returns the result
]]--
local function inject(host, port, injectable)
  local all = {}
  for k, v in pairs(injectable) do
    all = http.pipeline_add(v, nil, all, 'GET')
  end
  return http.pipeline_go(host, port, all)
end

--[[
Checks is received responses matches with usual sql error messages,
what potentially means that the host is vulnerable to sql injection.
]]--
local function check_responses(queries, responses)
  local results = {}
  for k, v in pairs(responses) do
    if (check_injection_response(v)) then
      table.insert(results, queries[k])
    end
  end
  return results
end

action = function(host, port)
  -- check for script arguments
  if stdnse.get_script_args('sql-injection.start') then
    start = stdnse.get_script_args('sql-injection.start')
  end

  if stdnse.get_script_args('sql-injection.maxdepth') then
    maxdepth = tonumber(stdnse.get_script_args('sql-injection.maxdepth'))
    stdnse.print_debug("maxdepth set to: " .. maxdepth)
  end

  -- crawl to find injectable urls
  local crawler = httpspider.Crawler:new(host, port, start, {scriptname = SCRIPT_NAME, maxpagecount = maxdepth})
  local injectable = {}

  while(true) do
    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(true, "ERROR: %s", r.reason)
      else
        break
      end
    end

    local links = httpspider.LinkExtractor:new(r.url, r.response.body, crawler.options):getLinks()
    for _,u in ipairs(links) do
      if url.parse(u).query then
        table.insert(injectable, u)
      end
    end
  end

  -- try to inject
  local results = {}
  if #injectable > 0 then
    stdnse.print_debug(1, "%s: Testing %d suspicious URLs", SCRIPT_NAME, #injectable)
    local injectableQs = build_injection_vector(injectable)
    local responses = inject(host, port, injectableQs)
    results = check_responses(injectableQs, responses)
  end

  if #results > 0 then
    return "Host might be vulnerable\n" .. table.concat(results, '\n')
  end

  return nil
end
