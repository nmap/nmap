local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves the version from the Cloudera HUE about page.
]]

---
-- @usage
-- nmap --script cloudera-hue-info -p 8888 host
--
-- @output
-- PORT     STATE SERVICE
-- 8888/tcp open  cloudera-hue
-- | cloudera-hue-info: 
-- |_  Version: 3.9.0


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({8888}, "cloudera-hue")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/about/"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match("<title>Hue.*</title>") then
      port.version.name = "cloudera-hue"
      port.version.product = "Cloudera HUE"
      local version = body:match('Hue&trade;%s(.-)%s[-]%s<a href="http://gethue.com"')
      stdnse.debug1("Cloudera Hue version %s",version)
      port.version.version = version
      nmap.set_port_version(host, port)
      table.insert(result, string.format("Version: %s", version))
    end
  end
  return stdnse.format_output(true, result)
end
