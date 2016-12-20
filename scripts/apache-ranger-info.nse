local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Discovers the Apache Ranger WebUI.
]]

---
-- @usage
-- nmap --script apache-ranger-info -p 6080 host
--
-- @output
-- PORT     STATE SERVICE
-- 6080/tcp open  apache-ranger-webui


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({6080}, "apache-ranger-webui")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/login.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match('<title>%s*Ranger %- Sign In%s*</title>') then
      port.version.name = "apache-ranger-webui"
      port.version.product = "Apache Ranger WebUI"
      nmap.set_port_version(host, port)
    end
  end
  return stdnse.format_output(true, result)
end
