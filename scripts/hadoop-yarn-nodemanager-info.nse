local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves information from the Hadoop YARN Node Manager WebUI.

Information gathered:
* Node Manager version
* Hadoop version
]]

---
-- @usage
-- nmap --script hadoop-yarn-nodemanager-info -p 8042 host
--
-- @output
-- PORT     STATE SERVICE
-- 8042/tcp open  hadoop-yarn-nodemanager
-- | hadoop-yarn-nodemanager-info: 
-- |   NM Version: 2.7.1.2.4.0.0-169 from 26104d8ac833884c8776473823007f176854f2eb by jenkins source checksum 95d56649315a4e29c8fc543f95da0aa on 2016-02-10T06:30Z
-- |_  Hadoop Version: 2.7.1.2.4.0.0-169 from 26104d8ac833884c8776473823007f176854f2eb by jenkins source checksum cf48a4c63aaec76a714c1897e2ba8be6 on 2016-02-10T06:18Z


author = "Thomas Debize"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({8042}, "hadoop-yarn-nodemanager")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function(host, port)

  local result = stdnse.output_table()
  local uri = "/node"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body'] then
    local body = response['body']:gsub("%%","%%%%")
    if body:match('<h3>%s*NodeManager%s*</h3>') then
      port.version.name = "hadoop-yarn-nodemanager"
      port.version.product = "Hadoop YARN Node Manager WebUI"
      
      local nm_version = body:match('Node Manager Version:.-<td>%s*(.-)%s*</td>')
      stdnse.debug1("Hadoop YARN Node Manager version %s",nm_version)
      table.insert(result, string.format("NM Version: %s", nm_version))
      
      local hadoop_version = body:match('Hadoop Version:.-<td>%s*(.-)%s*</td>')
      stdnse.debug1("Hadoop version %s",hadoop_version)
      table.insert(result, string.format("Hadoop Version: %s", hadoop_version))
      
      port.version.version = nm_version
      nmap.set_port_version(host, port)
    end
  end
  return stdnse.format_output(true, result)
end
