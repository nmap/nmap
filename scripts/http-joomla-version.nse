local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the joomla version by scraping the configuration XML file.
]]

---
--  @usage
--  nmap --script http-joomla-version <url>
--  nmap --script http-joomla-version all4share.net
--
--  @args http-joomla-version.url The url to scan.
--
--  @output
--    PORT   STATE SERVICE
--    80/tcp open  http
--    |_http-joomla-version: Version / Unable to retrieve the version
--    443/tcp open  http
--    |_http-joomla-version: Version / Unable to retrieve the version
--

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

-- Most probably checking port 443 isn't required.
-- If required enable the following command.
-- portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

portrule = shortport.port_or_service( {80}, {"http"}, "tcp", "open")

local scrap = function( host, port, path )
  local resp, version

  resp = http.get( host, port, path )

  -- try and match version tags
  version = string.match(resp.body, '<version>(.*)</version>')
  if( version ) then
    return version
  else
    return nil
  end
end

action = function(host, port)
  local version

  --[[ Sample Joomla websites ( >= 1.60 )
        http://www.itwire.com
        http://www.highcharts.com
    ]]
  -- This path applies to all versions of Joomla from 1.6.0 until 3.6.3
  -- (including, of course, all the versions in the 2.5.x line),
  -- which is excellent!
  version = scrap( host, port, "/administrator/manifests/files/joomla.xml" )
  if(version ~= nil) then
    return version
  end

  --[[ Sample Joomla websites ( >= 1.5.0 and <= 1.5.26 )
        http://www.pixeden.com
    ]]
  -- Joomla websites in the 1.5.x line do not have the joomla.xml file
  -- But luckily we got another XML file

  --[[ Note :
      To confuse the attackers, the few web admins maintain this XML file
      even if the version of Joomla website is >= 1.5.26
      Sample Joomla website for this case
        https://www.webempresa.com
    ]]
  version = scrap( host, port, "/language/en-GB/en-GB.xml" )
  if(version ~= nil) then
    return version
  end

  -- This path detects Joomla websites with version > 1.5
  version = scrap( host, port, "/modules/custom.xml" )
  if(version ~= nil) then
    return version
  else
    return "Unable to retrieve the Joomla version."
  end

end
