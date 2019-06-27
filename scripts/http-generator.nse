local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"

description = [[
Displays the contents of the "generator" meta tag of a web page (default: /)
if there is one.
]]

author = "Michael Kohl"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
-- 2014-07-29 Fabian Affolter <fabian@affolter-engineering.ch>:
--   + update generator pattern

portrule = shortport.http

action = function(host, port)
  local response, loc, generator
  local path = stdnse.get_script_args('http-generator.path') or '/'
  local redirects = tonumber(stdnse.get_script_args('http-generator.redirects')) or 3

  -- Worst case: <meta name=Generator content="Microsoft Word 11">
  local pattern = stringaux.ipattern('<meta name=[\"\']?generator[\"\']? content=[\"\']([^\"\']*)[\"\'] ?/?>')
  response = http.get(host, port, path, {redirect_ok=redirects})
  if ( response and response.body ) then
    return response.body:match(pattern)
  end
end
