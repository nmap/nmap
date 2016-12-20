local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves the version from the Cloudera Manager login page.
]]

---
-- @usage
-- nmap --script cloudera-manager-info -p 7180 host
--
-- @output
-- PORT     STATE SERVICE
-- 7180/tcp open  cloudera-manager
-- | cloudera-manager-info: 
-- |_  Version: 5.5.0


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({7180}, "cloudera-manager")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/cmf/login"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match("<title>Cloudera Manager</title>") then
      port.version.name = "cloudera-manager"
      port.version.product = "Cloudera Manager"
      local version = body:match("var clouderaManager.*version:%s'(.-)',")
      stdnse.debug1("Cloudera Manager version %s",version)
      port.version.version = version
      nmap.set_port_version(host, port)
      table.insert(result, string.format("Version: %s", version))
    end
  end
  return stdnse.format_output(true, result)
end
