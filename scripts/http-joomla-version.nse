local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the joomla version by scraping the configuration XML file.
]]

---
--@args http-joomla-version.url The url to scan.
-- Works for version >= 1.6
--@output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-joomla-version: Version / Unable to retrieve the version
-- 443/tcp open  http
-- |_http-joomla-version: Version / Unable to retrieve the version
--

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local resp, version

  --[[ Sample Joomla websites
        http://www.itwire.com
        http://www.highcharts.com
    ]]
  resp = http.get( host, port, "/administrator/manifests/files/joomla.xml" )

  -- try and match version tags
  version = string.match(resp.body, '<version>(.*)</version>')
  if( version ) then
    return version
  else
    return "Failed to retrieve the Joomla version."
  end
end
