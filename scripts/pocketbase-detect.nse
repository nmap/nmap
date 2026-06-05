local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
  Detects the PocketBase (Go-based backend) service and its default admin panel.
]]

---
-- @usage
-- nmap -p 8090 --script pocketbase-detect <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8090/tcp open  http
-- |_pocketbase-detect: PocketBase Backend detected! Admin panel: /_/
---

author = "Aykut Gokbulut"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- PocketBase uses 8090 by default, but it can also run on standard HTTP ports
portrule = shortport.port_or_service({80, 443, 8080, 8090}, "http")

action = function(host, port)
  local path = "/_/" -- Default PocketBase admin panel path
  local response = http.get(host, port, path)
  
  -- Check if the page is accessible and contains PocketBase-specific patterns
  if (response.status == 200 and response.body) then
    -- Look for 'pocketbase' string or 'pb-' variable prefixes in the response body
    if response.body:match("pocketbase") or response.body:match("pb%-") then
      return "PocketBase Backend detected! Admin panel: " .. path
    end
  end
  
  return nil
end
