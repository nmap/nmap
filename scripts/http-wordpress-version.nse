local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the WordPress version by scraping the readme page, meta tags and rss feeds.
]]

---
--  @usage
--  nmap --script http-wordpress-version <url>
--  nmap --script http-wordpress-version drupal.org
--
--  @args http-wordpress-version.url The url to scan.
--
--  @output
--    PORT   STATE SERVICE
--    80/tcp open  http
--    |_http-wordpress-version: Version / Unable to retrieve the version / Did not follow redirection
--    443/tcp open  http
--    |_http-wordpress-version: Version / Unable to retrieve the version
--

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local resp, version, regex

  -- Scraping the readme.html file for version.
  regex = '[V|v]ersion ([0-9 .]*)'
  resp = http.get( host, port, "/readme.html" )

  -- try and match version tags
  version = string.match(resp.body, regex)
  if( version ) then
    return version
  end

  -- Scraping the meta tags for version.
  regex =  '<meta name="generator" content="WordPress ([0-9 .]*)" />'
  resp = http.get( host, port, "/" )

  -- try and match version tags
  version = string.match(resp.body, regex)
  if( version ) then
    return version
  end

  -- Scraping the WordPress files for version.
  regex =  '/wp-includes\\/js\\/wp-emoji-release.min.js?ver=([0-9 .]*)'

  -- try and match version tags
  version = string.match(resp.body, regex)
  if( version ) then
    return version
  end

  -- Scraping all RSS feeds for finding version.
  links = {"?feed=rss", "?feed=rss2", "?feed=atom", "/feed", "/feed/", "/feed/rss/", "/feed/rss2/", "/feed/atom/"}
  regex = 'v=([0-9 .]*)</generator>'

  -- Iterating over every link of the RSS feed.
  for _, path in pairs(links) do
    resp = http.get( host, port, path )

    -- try and match version tags
    version = string.match(resp.body, regex)
    if( version ) then
      return version
    end
  end

  return "Unable to retrieve the Wordpress version."

end
