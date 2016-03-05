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
-- |   title: Apache Server Status for example.com (via 127.0.1.1)
-- |   Server Version:  Apache/2.4.12 (Ubuntu)
-- |   Server Built:  Jul 24 2015 15:59:00
-- |   Server Uptime:   47 seconds
-- |   Server Load:  0.00 0.02 0.05
-- |   requests: 
-- |      Srv PID Acc M CPU SS Req Conn Child Slot Client VHost Request 
-- |      0-0  20079 0/0/0 W  0.00 0 0 0.0 0.00 0.00 127.0.0.1 www.example.com:80 GET /server-status HTTP/1.1 
-- |_     1-0  20080 0/1/1 _ 0.02 15 0 0.0 0.00 0.00 127.0.0.1 www.example.com:80 GET /server-status HTTP/1.1 
-- 
-- @xmloutput
-- <elem key="title">Apache Server Status for example.com (via 127.0.1.1)</elem>
-- <elem key="Server Version"> Apache/2.4.12 (Ubuntu)</elem>
-- <elem key="Server Built"> Jul 24 2015 15:59:00</elem>
-- <elem key="Server Uptime">  47 seconds</elem>
-- <elem key="Server Load"> 0.00 0.02 0.05</elem>
-- <table key="requests">
-- <elem> Srv PID Acc M CPU SS Req Conn Child Slot Client VHost Request </elem>
-- <elem> 0-0  20079 0/0/0 W  0.00 0 0 0.0 0.00 0.00 127.0.0.1 www.example.com:80 GET /server-status HTTP/1.1 </elem>
-- <elem> 1-0  20080 0/1/1 _ 0.02 15 0 0.0 0.00 0.00 127.0.0.1 www.example.com:80 GET /server-status HTTP/1.1 </elem>
---

author = "Eric Gershman"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http
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
  result.title = string.match(response.body, "<h1>([^<]*)</h1>")
  result["Server Version"] = string.match(response.body, "Server%sVersion:([^<]*)</")
  result["Server Built"] = string.match(response.body, "Server%sBuilt:([^<]*)</")
  result["Server Uptime"] = string.match(response.body, "Server%suptime:([^<]*)</")
  result["Server Load"] = string.match(response.body, "Server%sload:([^<]*)</")

  result.requests = {}

  -- Parse the Apache client requests into the result table
  local results_table = string.match(response.body, "<table border=\"0\">.-</table>")
  for line in string.gmatch(results_table, "<tr><t[hd]>.-</t[hd]></tr>") do
    line = string.gsub (line, "\n", "")
    local request = ""
    for field in string.gmatch(line, ">([^<]*)</") do
      -- Add spaces between each field in the request
      request = request .. " " .. field
    end
    result.requests[#result.requests + 1] = request
  end

  return result
end
