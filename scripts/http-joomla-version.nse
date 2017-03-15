local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the joomla version from the XML file
]]

---
--@args http-title.url The url to fetch. Default: /
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-joomla-version: Version / Unable to retrieve the version
--

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, version

  -- Works for version >= 1.6
  -- http://www.itwire.com/administrator/manifests/files/joomla.xml
  resp = http.get( host, port, "/administrator/manifests/files/joomla.xml" )

  -- try and match version tags
  version = string.match(resp.body, '<version>(.*)</version>')
  if( version ) then
    return version
  else
    return "Failed to retrieve the Joomla version."
  end
end
