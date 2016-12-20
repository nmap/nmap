local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Discovers the Apache Oozie Web Console.
]]

---
-- @usage
-- nmap --script apache-oozie-webconsole-info -p 11000 host
--
-- @output
-- PORT      STATE SERVICE
-- 11000/tcp open  apache-oozie-webconsole


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({11000}, "hadoop-yarn-resourcemanager")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/oozie/"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match('<title>Oozie Web Console</title>') then
      port.version.name = "apache-oozie-webconsole"
      port.version.product = "Apache Oozie Web Console"
      nmap.set_port_version(host, port)
    end
  end
  return stdnse.format_output(true, result)
end
