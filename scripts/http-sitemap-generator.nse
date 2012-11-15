description = [[
Spiders a web server and displays its directory structure along with
number and types of files in each folder. Note that files listed as
having an 'Other' extension are ones that have no extension or that
are a root document.
]]

---
-- @usage
-- nmap --script http-sitemap-generator -p 80 <host>
--
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-sitemap-generator: 
-- |   Directory structure:
-- |     /
-- |       Other: 1
-- |     /images/
-- |       png: 1
-- |     /shared/css/
-- |       css: 1
-- |     /shared/images/
-- |       gif: 1; png: 1
-- |   Longest directory structure:
-- |     Depth: 2
-- |     Dir: /shared/css/
-- |   Total files found (by extension):
-- |_    Other: 1; css: 1; gif: 1; png: 2
--
-- @args http-sitemap-generator.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-sitemap-generator.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-sitemap-generator.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-sitemap-generator.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-sitemap-generator.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
--

author = "Piotr Olma"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

local shortport = require 'shortport'
local http = require 'http'
local stdnse = require 'stdnse'
local url = require 'url'
local httpspider = require 'httpspider'
local string = require 'string'
local table = require 'table'

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local function dict_add(d, k, v)
  if not d[k] then
    d[k] = {}
    d[k][v] = 1
  elseif d[k][v] then
    d[k][v] = d[k][v]+1
  else
    d[k][v] = 1
  end
end

local function map(f, t)
  local new_t = {}
  for _,v in ipairs(t) do
    new_t[#new_t+1] = f(v)
  end
  return new_t
end

local function sort_dirs(t)
  local keys_table = {}
  for k,_ in pairs(t) do
    keys_table[#keys_table+1] = k
  end
  table.sort(keys_table)
  local newdirs = {}
  map(function(d) newdirs[#newdirs+1]={d, t[d]} end, keys_table)
  return newdirs
end

local function sort_by_keys(t)
  local keys_table = {}
  for k,_ in pairs(t) do
    keys_table[#keys_table+1] = k
  end
  table.sort(keys_table)
  return map(function(e) return e..": "..tostring(t[e]) end, keys_table)
end

local function internal_table_to_output(t)
  local output = {}
  for _,dir in ipairs(t) do
    local ext_and_occurences = sort_by_keys(dir[2])
    output[#output+1] = {name=dir[1], table.concat(ext_and_occurences, "; ")}
  end
  return output
end

local function get_file_extension(f)
  return string.match(f, ".-/.-%.([^/%.]*)$") or "Other"
end

-- removes /../ from paths; for example
-- normalize_path("/a/v/../../da/as/d/a/a/aa/../") -> "/da/as/d/a/a/"
local function normalize_path(p)
  local n=0
  repeat
    p, n = string.gsub(p, "/[^/]-/%.%.", "")
  until n==0
  return p
end

function action(host, port)
  local starting_url = stdnse.get_script_args('http-sitemap-generator.url') or "/"
  
  -- create a new crawler instance
	local crawler = httpspider.Crawler:new(	host, port, nil, { scriptname = SCRIPT_NAME, noblacklist=true, useheadfornonwebfiles=true } )
  
	if ( not(crawler) ) then
		return
	end
  
	local visited = {}
  local dir_structure = {}
  local total_ext = {}
  local longest_dir_structure = {dir="/", depth=0}
	while(true) do
	  local status, r = crawler:crawl()
    
	  if ( not(status) ) then
		  if ( r.err ) then
			  return stdnse.format_output(true, ("ERROR: %s"):format(r.reason))
		  else
			  break
		  end
	  end
	  if r.response.status and r.response.status == 200 then
	    --check if we've already visited this file
	    local path = normalize_path(r.url.path)
	    if not visited[path] then
	      local ext = get_file_extension(path)
	      if total_ext[ext] then total_ext[ext]=total_ext[ext]+1 else total_ext[ext]=1 end
	      local dir = normalize_path(r.url.dir)
	      local _,dir_depth = string.gsub(dir,"/","/")
	      -- check if this path is the longest one
	      dir_depth = dir_depth - 1 -- first '/'
	      if dir_depth > longest_dir_structure["depth"] then
	        longest_dir_structure["dir"] = dir
	        longest_dir_structure["depth"] = dir_depth
	      end
        dict_add(dir_structure, dir, ext)
        -- when withinhost=false, then maybe we'd like to include the full url
        -- with each path listed in the output
        visited[path] = true
      end
	  end
	end
  
	local out = internal_table_to_output(sort_dirs(dir_structure))
	local tot = sort_by_keys(total_ext)
	out =
	{
	  "Directory structure:", out,
	  {name="Longest directory structure:", "Depth: "..tostring(longest_dir_structure.depth), "Dir: "..longest_dir_structure.dir},
	  {name="Total files found (by extension):", table.concat(tot, "; ")}
	}
	return stdnse.format_output(true, out)
end

