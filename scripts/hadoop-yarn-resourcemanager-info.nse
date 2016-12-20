local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves information from the Hadoop YARN Resource Manager WebUI.

Information gathered:
* ResourceManager state
* ResourceManager version
* Hadoop version
]]

---
-- @usage
-- nmap --script hadoop-yarn-resourcemanager-info -p 8088 host
--
-- @output
-- PORT     STATE SERVICE
-- 8088/tcp open  hadoop-yarn-resourcemanager
-- | hadoop-yarn-resourcemanager-info: 
-- |   State: STARTED
-- |   RM Version: 2.6.0-cdh5.5.0 from fd21232cef7b8c1f536965897ce20f50b83ee7b2 by jenkins source checksum db52b8a74b1a7e55c309ec5fbcd7ca on 2015-11-09T20:43Z
-- |_  Hadoop Version: 2.6.0-cdh5.5.0 from fd21232cef7b8c1f536965897ce20f50b83ee7b2 by jenkins source checksum 98e07176d1787150a6a9c087627562c on 2015-11-09T20:37Z


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({8088}, "hadoop-yarn-resourcemanager")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/cluster/cluster"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match('<title>%s*About the Cluster%s*</title>') then
      port.version.name = "hadoop-yarn-resourcemanager"
      port.version.product = "Hadoop YARN Resource Manager WebUI"
      
      local state = body:match('ResourceManager state:.-<td>%s*(.-)%s*</td>')
      stdnse.debug1("Hadoop YARN Resource Manager state %s",state)
      table.insert(result, string.format("State: %s", state))
      
      local rm_version = body:match('ResourceManager version:.-<td>%s*(.-)%s*</td>')
      stdnse.debug1("Hadoop YARN Resource Manager version %s",rm_version)
      table.insert(result, string.format("RM Version: %s", rm_version))
      
      local hadoop_version = body:match('Hadoop version:.-<td>%s*(.-)%s*</td>')
      stdnse.debug1("Hadoop version %s",hadoop_version)
      table.insert(result, string.format("Hadoop Version: %s", hadoop_version))
      
      port.version.version = rm_version
      nmap.set_port_version(host, port)
    end
  end
  return stdnse.format_output(true, result)
end
