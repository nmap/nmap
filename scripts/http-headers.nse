local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.
]]

---
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-headers:
-- |   Date: Fri, 25 Jan 2013 17:39:08 GMT
-- |   Server: Apache/2.2.14 (Ubuntu)
-- |   Accept-Ranges: bytes
-- |   Vary: Accept-Encoding
-- |   Connection: close
-- |   Content-Type: text/html
-- |
-- |_  (Request type: HEAD)
--
--@args path The path to request, such as <code>/index.php</code>. Default <code>/</code>.
--@args useget Set to force GET requests instead of HEAD.
--
--@see http-security-headers.nse

author = "Ron Bowes"

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

  if not (result and result.status) then
    return fail("Header request failed")
  end

  table.insert(result.rawheader, "(Request type: " .. request_type .. ")")

  return stdnse.format_output(true, result.rawheader)
end
