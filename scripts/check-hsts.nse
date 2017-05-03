local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Performs a HEAD request for the root folder ("/") or path argument of a web server and displays if a HSTS is enabled or disabled. based on http-headers.nse
]]

---
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | check-hsts:
--  _HSTS disabled. - Possily unsafe

--
--@args path The path to request, such as <code>/index.php</code>. Default <code>/</code>.
--@args useget Set to force GET requests instead of HEAD.

author = "Jose Carlos Ramos"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
  local request_type = "HEAD"
  local status = false
  local result

  -- Check if the user didn't want HEAD to be used
  if(useget == nil) then
    -- Try using HEAD first
    status, result = http.can_use_head(host, port, nil, path)
  end

  -- If head failed, try using GET
  if(status == false) then
    stdnse.debug1("HEAD request failed, falling back to GET")
    result = http.get(host, port, path)
    request_type = "GET"
  end

  if(result == nil) then
    return fail("Header request failed")
  end

  if(result.rawheader == nil) then
    return fail("Header request didn't return a proper header")
  end

  table.insert(result.rawheader, "(Request type: " .. request_type .. ")")
  

  if(result.header['strict-transport-security']) then
      table.insert(result.header, "(Request type: " .. request_type .. ")")
      return stdnse.format_output(true, "HSTS enabled!")
  else
      return stdnse.format_output(true, "HSTS disabled. - Possily unsafe")
  end
  

  --return stdnse.format_output(true, result.rawheader)
end
