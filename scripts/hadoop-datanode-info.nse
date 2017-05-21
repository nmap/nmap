local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Discovers information such as log directories from an Apache Hadoop DataNode
HTTP status page.

Information gathered:
* Log directory (relative to http://host:port/)
]]

---
-- @usage
-- nmap --script hadoop-datanode-info.nse -p 50075 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 50075/tcp open  hadoop-datanode syn-ack
-- | hadoop-datanode-info:
-- |_  Logs: /logs/
--
-- @xmloutput
-- <elem key="Logs">/logs/</elem>


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service({50075}, "hadoop-datanode")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

  local result = stdnse.output_table()
  local uri = "/browseDirectory.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
    local body = response['body']:gsub("%%","%%%%")
    stdnse.debug2("Body %s\n",body)
    if body:match("([^][\"]+)\">Log") then
      port.version.name = "hadoop-datanode"
      port.version.product = "Apache Hadoop"
      nmap.set_port_version(host, port)
      local logs = body:match("([^][\"]+)\">Log")
      stdnse.debug1("Logs %s",logs)
      result["Logs"] = logs
    end
    return result
  end
end
