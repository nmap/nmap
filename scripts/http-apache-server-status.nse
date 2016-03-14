local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to retrieve the server-status page for Apache webservers that
have mod_status enabled. If the server-status page exists and appears to
be from mod_status the script will parse useful information such as the
system uptime, Apache version and recent HTTP requests.

References:
* http://httpd.apache.org/docs/2.4/mod/mod_status.html
* https://blog.sucuri.net/2012/10/popular-sites-with-apache-server-status-enabled.html
* https://www.exploit-db.com/ghdb/1355/
* https://github.com/michenriksen/nmap-scripts
]]

---
--@usage nmap -p80 --script http-apache-server-status <target>
--@usage nmap -sV --script http-apache-server-status <target>
--
--@output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-apache-server-status:
-- |   Heading: Apache Server Status for example.com (via 127.0.1.1)
-- |   Server Version:  Apache/2.4.12 (Ubuntu)
-- |   Server Built:  Jul 24 2015 15:59:00
-- |   Server Uptime:   53 minutes 31 seconds
-- |   Server Load:  0.00 0.01 0.05
-- |   VHosts:
-- |_    www.example.com:80  GET /server-status HTTP/1.1
--
-- @xmloutput
-- <elem key="Heading">Apache Server Status for example.com (via 127.0.1.1)</elem>
-- <elem key="Server Version">Apache/2.4.12 (Ubuntu)</elem>
-- <elem key="Server Built">Jul 24 2015 15:59:00</elem>
-- <elem key="Server Uptime">59 minutes 26 seconds</elem>
-- <elem key="Server Load">0.01 0.02 0.05</elem>
-- <table key="VHosts">
--   <elem>www.example.com:80</elem>
-- </table>

author = "Eric Gershman"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  if not shortport.http(host, port) then
    return false
  end
  if port.version and port.version.product then
    return string.match(port.version.product, "Apache")
  end
  return true
end

action = function(host, port)
  -- Perform a GET request for /server-status
  local path = "/server-status"
  local response = http.get(host,port,path)
  local result = {}

  -- Fail if there is no data in the response, the response body or if the HTTP status code is not successful
  if not response or not response.status or response.status ~= 200 or not response.body then
    stdnse.debug(1, "Failed to retrieve: %s", path)
    return
  end

  -- Fail if this doesn't appear to be an Apache mod_status page
  if not string.match(response.body, "Apache%sServer%sStatus") then
    stdnse.debug(1, "%s does not appear to be a mod_status page", path)
    return
  end

  result = stdnse.output_table()

  -- Remove line breaks from response.body to handle html tags that span multiple lines
  response.body = string.gsub(response.body, "\n", "")

  -- Add useful data to the result table
  result["Heading"] = string.match(response.body, "<h1>([^<]*)</h1>")
  result["Server Version"] = string.match(response.body, "Server%sVersion:%s*([^<]*)</")
  result["Server Built"] = string.match(response.body, "Server%sBuilt:%s*([^<]*)</")
  result["Server Uptime"] = string.match(response.body, "Server%suptime:%s*([^<]*)</")
  result["Server Load"] = string.match(response.body, "Server%sload:%s*([^<]*)</")

  port.version = port.version or {}
  if port.version.product == nil and (port.version.name_confidence or 0) <= 3 then
    port.version.service = "http"
    port.version.product = "Apache httpd"
    local cpe = "cpe:/a:apache:http_server"
    local version, extra = string.match(result["Server Version"], "^Apache/([%w._-]+)%s*(.-)$")
    if version then
      cpe = cpe .. ":" .. version
      port.version.version = version
    end
    if extra then
      port.version.extrainfo = extra
    end
    port.version.cpe = port.version.cpe or {}
    table.insert(port.version.cpe, cpe)
    nmap.set_port_version(host, port, "hardmatched")
  end

  result.VHosts = {}
  local uniq_requests = {}

  -- Parse the Apache client requests into the result table
  for line in string.gmatch(response.body, "<td nowrap>.-</td></tr>") do
    -- skip line if the request is empty
    if not string.match(line, "<td%snowrap></td><td%snowrap></td></tr>") then
      local vhost = string.match(line, ">([^<]*)</td><td")
      uniq_requests[vhost] = 1
    end
  end
  for request,count in pairs(uniq_requests) do
    table.insert(result.VHosts,request)
  end
  table.sort(result.VHosts)

  return result
end
