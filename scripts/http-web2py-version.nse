local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects the web2py version running on port 80 or 8000 by finding the diff in admin's html, default page's html and javascript file of default app of the server that is running. At present a basic distinguision is made on the basis of <=2.10.x, 2.11.x, 2.12.x, 2.13.x, 2.14.x(latest stable version).
]]

---
-- @usage
-- nmap --script http-web2py-version <site-url>
-- nmap --script http-web2py-version scanme.nmap.org
--
-- @args http-django-version.url. The url to scan.
--
-- @output
--	PORT    STATE    SERVICE
-- 	80/tcp  open     http
--  |_http-django-version: Version = x.y.z
--  8000/tcp open  http
--  |_http-django-version: Version = x.y.z
--

author = "capt2101akash"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default","discovery","safe"}

portrule = shortport.port_or_service({80,8000}, {"http","https"}, "tcp", "open")

local parse = function(host, port, path)
  local response, version, str
  
  response = http.get(host, port, path)
  
  -- check for pattern in admin .html

  if(string.find(path, "admin")) then
    stdnse.debug("In admin")
    if(string.find(response.body,"w2p_flash alert") and string.find(response.body,":input")) then
      version = "Version >=2.14.x"
      return version
    end
    if(string.find(response.body,"flash alert") and string.find(response.body, ":input")) then
      version = "Version = 2.13.x"
      return version
    end
  end
  
  -- check for pattern in default app for versions <=2.12.x
 
  if(string.find(path, "index")) then
    if(string.find(response.body, "main-container") and string.find(response.body, "navbar-inverse")) then
      version = "Version = 2.12.x"
      return version
    end
  end

  -- check for pattern in javascript file for versions <= 2.11.x
  
  if(string.find(path, "js")) then
    check = string.find(response.body, "main-container")
    if(string.find(response.body, "if(confirm_message != undefined)") and not(check)) then
      version = "Version = 2.11.x"
      return version
    end
  end
    
end


action = function(host, port)
  local version 

  version = parse(host, port, "/admin")
  
  if(version ~= nil) then
    return version
  end
  

  version = parse(host, port, "/welcome/default/index")
  if(version ~= nil) then
    return version
  end
  

  version = parse(host, port, "/welcome/static/js/web2py.js")
  if(version ~= nil) then
    return version
  end

  -- If no above the following pattern matches then it shows following version
  return "Version <= 2.10.x"
end
