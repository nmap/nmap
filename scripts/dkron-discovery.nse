local shortport =  require "shortport"
local http = require "http"
local nmap = require "nmap"
local table = require "table"
local stdnse = require "stdnse"

description = [[
Dkron is a system service for workload automation that runs scheduled jobs, just like the cron unix service but distributed in several machines in a cluster. Default TCP port is 8080. This script will access the URI /dashboard from a dkron service and get it version.
]]

---
-- @usage
-- nmap -p 8080 --script dkron-discovery.nse <target>
--
-- @output
--PORT     STATE SERVICE
--8080/tcp open  http
--| dkron-discovery: 
--|   Installed version:3.0.6
--|_  Directory /dashboard is accessible!
--

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service(8080, "dkron", "tcp")

action = function(host, port)
  local http_response = http.get(host, port, "/dashboard")
  local dkron_response = {}

  if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
    return
  end
 
  dkron_version = string.match(http_response.rawbody, "Dkron %d.%d.%d")
  if dkron_version then
    port.version.name = "http"
    port.version.version = dkron_version
    port.version.product = "dKron"
    nmap.set_port_version(host, port)
    table.insert(dkron_response, {"Installed version: " .. dkron_version,"Directory /dashboard is accessible!"})

    return stdnse.format_output(true, dkron_response)
  end
end
