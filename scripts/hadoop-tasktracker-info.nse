local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Retrieves information from an Apache Hadoop TaskTracker HTTP status page.

Information gathered:
* Hadoop version
* Hadoop Compile date
* Log directory (relative to http://host:port/)
]]

---
-- @usage
-- nmap --script hadoop-tasktracker-info -p 50060 host
--
-- @output
-- PORT      STATE SERVICE            REASON
-- 50060/tcp open  hadoop-tasktracker syn-ack
-- | hadoop-tasktracker-info:
-- |   Version: 0.20.1 (f415ef415ef415ef415ef415ef415ef415ef415e)
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |_  Logs: /logs/
--
-- @xmloutput
-- <elem key="Version">0.20.1 (f415ef415ef415ef415ef415ef415ef415ef415e)</elem>
-- <elem key="Compiled">Wed May 11 22:33:44 PDT 2011 by bob from unknown</elem>
-- <elem key="Logs">/logs/</elem>


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({50060}, "hadoop-tasktracker")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

  local result = stdnse.output_table()
  local uri = "/tasktracker.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
    local body = response['body']:gsub("%%","%%%%")
    stdnse.debug2("Body %s\n",body)
    if response['body']:match("Version:</b>%s*([^][<]+)") then
      local version = response['body']:match("Version:</b>%s*([^][<]+)")
      local versionNo = version:match("([^][,]+)")
      local versionHash = version:match("[^][,]+%s+(%w+)")
      stdnse.debug1("Version %s (%s)",versionNo,versionHash)
      result["Version"] = ("%s (%s)"):format(versionNo, versionHash)
      port.version.version = version
    end
    if response['body']:match("Compiled:</b>%s*([^][<]+)") then
      local compiled = response['body']:match("Compiled:</b>%s*([^][<]+)"):gsub("%s+", " ")
      stdnse.debug1("Compiled %s",compiled)
      result["Compiled"] = compiled
    end
    if body:match("([^][\"]+)\">Log") then
      local logs = body:match("([^][\"]+)\">Log")
      stdnse.debug1("Logs %s",logs)
      result["Logs"] = logs
    end
    if #result > 0 then
      port.version.name = "hadoop-tasktracker"
      port.version.product = "Apache Hadoop"
      nmap.set_port_version(host, port)
      return result
    end
  end
end
