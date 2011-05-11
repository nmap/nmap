description = [[
Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL
injection attack.

The script spiders an HTTP server looking for URLs containing queries. It then
proceeds to combine crafted SQL commands with susceptible URLs in order to
obtain errors. The errors are analysed to see if the URL is vulnerable to
attack. This uses the most basic form of SQL injection but anything more
complicated is better suited to a standalone tool. Both meta-style and HTTP redirects
are supported.

We may not have access to the target web server's true hostname, which can prevent access to
virtually hosted sites.  This script only follows absolute links when the host name component is the same as the target server's reverse-DNS name.
]]

require('url')
require('shortport')
require('stdnse')
require('strbuf')
require('listop')
require('comm')
require('http')
require('nsedebug')

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

-- Change this to increase depth of crawl
local maxdepth = 10
local get_page_from_host

local soc
local catch = function() soc:close() end
local try = nmap.new_try(catch)

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

--[[
Follow redirects, Instead of adding redirects to the url list
we just modify it's format so the parser logic can be applied to
it in find_links()
--]]

local function check_redirects(page) 
  local lpage = string.lower(page)
  local _, httpurl = nil

  -- meta redirects
  if(string.find(lpage, '<%s*meta%s*http%-equiv%s*=%s*"%s*refresh%s*"')) then
    _, _, httpurl = string.find(lpage, 'content%s*=%s*"%s*%d+%s*;%s*url%s*=%s*([^"]+)"')
    if httpurl then
      page = page .. 'href="' .. httpurl .. '"'
    end
  end

  -- http redirect
  if(string.find(lpage, 'HTTP/1.1 301 moved permanently')) then
    _, _, httpurl = string.find(lpage, 'location:%s*([^\n]+)')	
    if httpurl then
      page = page .. 'href="' .. httpurl .. '"'
    end
  end

  return page
end

--[[
True if url is local to the site we're scanning. We never should spider 
away from current site!
--]]

local function is_local_link(url_parts, host) 
  if url_parts.authority and not(url_parts.authority == host.name) then
    return false
  end
  return true
end

--[[
Parse a html document looking for href links. If a local link is found
it is added to the spider list If a link with a query is found it is 
added to the inject list, which is returned.
--]]

local function find_links(list, base_path, page, host) 
  local httpurl,injectable, url_parts
  local i, s, e

  injectable = {}
  url_parts = {}
	
  for w in string.gmatch(page, 'href%s*=%s*"%s*[^"]+%s*"') do
    s, e = string.find(w, '"')
    httpurl = string.sub(w, s+1, #w-1)
    i = 1

    -- parse out duplicates, otherwise we'll be here all day 
    while list[i] and not(list[i] == httpurl) do
      i = i + 1
    end

    url_parts = url.parse(httpurl)

    if list[i] == nil and is_local_link(url_parts, host) and 
      (not url_parts.scheme or url_parts.scheme == "http") then
        httpurl = url.absolute(base_path, httpurl)
	table.insert(list, httpurl)
	if url_parts.query then 
	  table.insert(injectable, httpurl) 
	end
    end
  end
  return injectable
end

action = function(host, port)
  local urllist, injectable 
  local results = {}
  local links, i, page
  local injectableQs
	
  i = 1 
  urllist = {}
  injectable = {}

  -- start at the root
  if nmap.registry.args['sql-injection.start'] then
    table.insert(urllist, "/" .. nmap.registry.args['sql-injection.start'])
  else
    table.insert(urllist, "/")
  end

  -- check for argument supplied max depth
  if nmap.registry.args['sql-injection.maxdepth'] then
    maxdepth = tonumber(nmap.registry.args['sql-injection.maxdepth'])
    stdnse.print_debug("maxdepth set to: " .. maxdepth)
  end

  while not(urllist[i] == nil) and i <= maxdepth do
    page = http.get(host, port, urllist[i], nil, nil)
    page = check_redirects(page.body)
    links = find_links(urllist, urllist[i], page, host)
    -- store all urls with queries for later analysis
    injectable = listop.append(injectable, links)
    i = i + 1
  end

  if #injectable > 0 then
    stdnse.print_debug(1, "%s: Testing %d suspicious URLs", SCRIPT_NAME, #injectable )
    -- test all potentially vulnerable queries
    injectableQs = build_injection_vector(injectable)
    local responses = inject(host, port, injectableQs)
    results = check_responses(injectableQs, responses)        
  end

  -- we can get multiple vulnerable URLS from a single query
  --results = listop.flatten(results);

  --if not listop.is_empty(results) then
  if #results > 0 then
    return "Host might be vulnerable\n" .. table.concat(results, '\n')
  end

  return nil
end
