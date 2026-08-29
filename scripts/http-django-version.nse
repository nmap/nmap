local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the django version running on port 80 or 8000 by finding the diff in admin UI of the server that is running. At present a basic division of version >=1.5 and <1.5 is done.
]]

---
-- @usage
-- nmap --script http-django-version <site-url>
-- nmap --script http-django-version scanme.nmap.org
--
-- @args http-django-version.url. The url to scan.
--
-- @output
--	PORT    STATE    SERVICE
-- 	80/tcp  open     http
--  |_http-django-version: Django version / Unable to retrieve /admin
--  8000/tcp open  http
--  |_http-django-version: Django version / Unable to retrieve the /admin
--

author = "capt2101akash"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default","discovery","safe"}

portrule = shortport.port_or_service({80,8000}, {"http"}, "tcp", "open")

local parse = function(host, port, path)
  local response, version, str
  
  response = http.get(host, port, path)
  
  -- check for pattern in admin .html
  if (string.match(response.body, '<h1>Not Found</h1>')) then
    return "No Django server running"
  else
    str = string.match(response.body, '<div id="branding">(.*)</div>')
    if (str) then
      version = ">=1.5"
      return version
    else
      version = "<=1.5"
      return version
    end
  end
end


action = function(host, port)
  local version 

  version = parse(host, port, "/admin")
  
  if(version) then
    return version
  
  else
    return "Unable to retrieve /admin."
  end

end
