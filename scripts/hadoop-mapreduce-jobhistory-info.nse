local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Discovers the Hadoop MapReduce JobHistory WebUI.
]]

---
-- @usage
-- nmap --script hadoop-mapreduce-jobhistory-info -p 19888 host
--
-- @output
-- PORT      STATE SERVICE
-- 19888/tcp open  hadoop-mapreduce-jobhistory


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({19888}, "hadoop-mapreduce-jobhistory")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/jobhistory"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match('<title>%s*JobHistory%s*</title>') then
      port.version.name = "hadoop-mapreduce-jobhistory"
      port.version.product = "Hadoop MapReduce JobHistory WebUI"
      nmap.set_port_version(host, port)
    end
  end
  return stdnse.format_output(true, result)
end
