local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Displays the contents of the "generator" meta tag of a web page (default: /) if there is one.
]]

author = "Michael Kohl"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @usage
-- nmap --script http-generator [--script-args http-generator.path=<path>,http-generator.redirects=<number>,...] <host>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- |_http-generator: TYPO3 4.2 CMS
-- 443/tcp open  https
-- |_http-generator: TYPO3 4.2 CMS
--
-- @args http-generator.path Specify the path you want to check for a generator meta tag (default to '/').
-- @args http-generator.redirects Specify the maximum number of redirects to follow (defaults to 3).

-- Changelog:
-- 2011-12-23 Michael Kohl <citizen428@gmail.com>:
--   + Initial version
-- 2012-01-10 Michael Kohl <citizen428@gmail.com>:
--   + update documentation
--   + make pattern case insensitive
--   + only follow first redirect
-- 2012-01-11 Michael Kohl <citizen428@gmail.com>:
--   + more generic pattern
--   + simplified matching
-- 2012-01-13 Michael Kohl <citizen428@gmail.com>:
--   + add http-generator.path argument
--   + add http-generator.redirects argument
--   + restructure redirect handling
--   + improve redirect pattern
--   + update documentation
--   + add changelog

-- TODO:
-- more generic generator pattern


-- helper function
local follow_redirects = function(host, port, path, n)
   local pattern = "^[hH][tT][tT][pP]/1.[01] 30[12]"
   local response = http.get(host, port, path)

   while (response['status-line'] or ""):match(pattern) and n > 0 do
      n = n - 1
      local loc = response.header['location']
      response = http.get_url(loc)
   end

   return response
end

portrule = shortport.http

action = function(host, port)
   local response, loc, generator
   local path = stdnse.get_script_args('http-generator.path') or '/'
   local redirects = tonumber(stdnse.get_script_args('http-generator.redirects')) or 3

   -- Worst case: <meta name=Generator content="Microsoft Word 11">
   local pattern = '<meta name="?generator"? content="([^\"]*)" ?/?>'

   -- make pattern case-insensitive
   pattern = pattern:gsub("%a", function (c)
               return string.format("[%s%s]", string.lower(c),
                                              string.upper(c))
             end)

   response = follow_redirects(host, port, path, redirects)
   if ( response and response.body ) then
     return response.body:match(pattern)
   end
end
