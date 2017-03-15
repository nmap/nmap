local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the drupal version by scraping the index page.
]]

---
--  @usage
--  nmap --script http-drupal-version <url>
--  nmap --script http-drupal-version drupal.org
--
--  @args http-drupal-version.url The url to scan.
--
--  @output
--    PORT   STATE SERVICE
--    80/tcp open  http
--    |_http-drupal-version: Version / Unable to retrieve the version / Did not follow redirection
--    443/tcp open  http
--    |_http-drupal-version: Version / Unable to retrieve the version
--

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local resp, version, regex
  regex = '<meta name="[G|g]enerator" content="Drupal ([0-9 .]*)'

  resp = http.get( host, port, "/" )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  -- try and match version tags
  version = string.match(resp.body, regex)
  if( version ) then
    return version
  else
    return "Unable to retrieve the Drupal version."
  end
end
