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

author = "Eddie Bell <ejlbell@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}
runlevel = 1.0

-- Change this to increase depth of crawl
local maxdepth = 10
local get_page_from_host

local soc
local catch = function() soc:close() end
local try = nmap.new_try(catch)

portrule = shortport.port_or_service({80, 443}, {"http","https"})

--[[
Download a page from host:port http server. The url is passed 
straight to the get request, so shouldn't include the domain name
--]]

local function get_page(host, port, httpurl) 
	local lines = ""
	local status = true
	local response = ""
	local opts = {timeout=10000, recv_before=false}

	-- connect to webserver 
	--soc = nmap.new_socket()
	--soc:set_timeout(4000)
	--try(soc:connect(host.ip, port.number))

	httpurl = string.gsub(httpurl, "&amp;", "&")
	--print(filename .. ": " .. httpurl) 

	-- request page
	local query = strbuf.new()
	query = query .. "GET " .. httpurl .. " HTTP/1.1"
	query = query .. "Accept: */*"
	query = query .. "Accept-Language: en"
	query = query .. "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"
	query = query .. "Host: " .. host.ip .. ":" .. port.number 
	--try(soc:send(strbuf.dump(query, '\r\n') .. '\r\n\r\n'))

	soc, response, bopt = comm.tryssl(host, port, strbuf.dump(query, '\r\n') .. '\r\n\r\n' , opts)
	while true do
		status, lines = soc:receive_lines(1)
		if not status then break end
		response = response .. lines
	end

	soc:close()
	return response
end

-- Curried function: so we don't have to pass port and host around
local function get_page_curried(host, port)
	return function(url)
		return get_page(host, port, url)
	end
end

--[[
Pattern match response from a submitted injection query to see
if it is vulnerable
--]]

local function check_injection_response(response)

	if not (string.find(response, 'HTTP/1.1 200 OK')) then
		return false 
	end

	response = string.lower(response)

	return (string.find(response, "invalid query") or
		string.find(response, "sql syntax") or
		string.find(response, "odbc drivers error"))
end

--[[
Parse urls with queries and transform them into potentially 
injectable urls. 
--]]

local function enumerate_inject_codes(injectable) 
	local utab, k, v, urlstr, response
	local qtab, old_qtab, results

	results = {}
	utab = url.parse(injectable)
	qtab = url.parse_query(utab.query)

	for k, v in pairs(qtab) do
		old_qtab = qtab[k];
		qtab[k] = qtab[k] .. "'%20OR%20sqlspider"

		utab.query = url.build_query(qtab)
		urlstr = url.build(utab)
		response = get_page_from_host(urlstr)

		if (check_injection_response(response)) then
			table.insert(results, urlstr)
		end 

		qtab[k] = old_qtab
		utab.query = url.build_query(qtab)
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
	if url_parts.authority and 
	   not(url_parts.authority == host.name) then
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
		httpurl = string.sub(w, s+1, string.len(w)-1)
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
	local urllist, results, injectable 
	local links, i, page
	
	i = 1 
	urllist = {}
	injectable = {}
	get_page_from_host = get_page_curried(host, port)

	-- start at the root
	table.insert(urllist, "/")

	while not(urllist[i] == nil) and i <= maxdepth do
		page = get_page_from_host(urllist[i])
		page = check_redirects(page)
		links = find_links(urllist, urllist[i], page, host)
		-- store all urls with queries for later analysis
		injectable = listop.append(injectable, links)
		i = i + 1
	end

	if #injectable > 0 then
		stdnse.print_debug(1, "%s: Testing %d suspicious URLs", filename, #injectable )
	end

	-- test all potentially vulnerable queries
	results = listop.map(enumerate_inject_codes, injectable)
	-- we can get multiple vulnerable URLS from a single query
	results = listop.flatten(results);

	if not listop.is_empty(results) then
		return "Host might be vulnerable\n" .. table.concat(results, '\n')
	end

	return nil
end
