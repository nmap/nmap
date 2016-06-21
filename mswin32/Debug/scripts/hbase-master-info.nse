local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache HBase (Hadoop database) master HTTP status page.

Information gathered:
* Hbase version
* Hbase compile date
* Hbase root directory
* Hadoop version
* Hadoop compile date
* Average load
* Zookeeper quorum server
* Associated region servers
]]

---
-- @usage
-- nmap --script hbase-master-info -p 60010 host
--
-- @output
-- | hbase-master-info:
-- |   Hbase Version: 0.90.1
-- |   Hbase Compiled: Wed May 11 22:33:44 PDT 2011, bob
-- |   HBase Root Directory: hdfs://master.example.com:8020/hbase
-- |   Hadoop Version: 0.20  f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Hadoop Compiled: Wed May 11 22:33:44 PDT 2011, bob
-- |   Average Load: 0.12
-- |   Zookeeper Quorum: zookeeper.example.com:2181
-- |   Region Servers:
-- |     region1.example.com:60030
-- |_    region2.example.com:60030
-- @xmloutput
-- <elem key="Hbase Version">0.90.1</elem>
-- <elem key="Hbase Compiled">Wed May 11 22:33:44 PDT 2011, bob</elem>
-- <elem key="HBase Root Directory">hdfs://master.example.com:8020/hbase</elem>
-- <elem key="Hadoop Version">0.20  f415ef415ef415ef415ef415ef415ef415ef415e</elem>
-- <elem key="Hadoop Compiled">Wed May 11 22:33:44 PDT 2011, bob</elem>
-- <elem key="Average Load">0.12</elem>
-- <elem key="Zookeeper Quorum">zookeeper.example.com:2181</elem>
-- <table key="Region Servers">
--   <elem>region1.example.com:60030</elem>
--   <elem>region2.example.com:60030</elem>
-- </table>


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({60010}, "hbase-master")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

  local result = stdnse.output_table()
  local region_servers = {}
  local uri = "/master.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if not (response['status-line'] and response['status-line']:match("200%s+OK") and response['body']) then
    return nil
  end
  local body = response['body']:gsub("%%","%%%%")
  stdnse.debug2("Body %s\n",body)
  if body:match("HBase%s+Version</td><td>([^][<]+)") then
    local version = body:match("HBase%s+Version</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Hbase  Version %s",version)
    result["Hbase Version"] = version
    port.version.version = version
  end
  if body:match("HBase%s+Compiled</td><td>([^][<]+)") then
    local compiled = body:match("HBase%s+Compiled</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Hbase Compiled %s",compiled)
    result["Hbase Compiled"] = compiled
  end
  if body:match("Directory</td><td>([^][<]+)") then
    local compiled = body:match("Directory</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("HBase RootDirectory %s",compiled)
    result["HBase Root Directory"] = compiled
  end
  if body:match("Hadoop%s+Version</td><td>([^][<]+)") then
    local version = body:match("Hadoop%s+Version</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Hadoop Version %s",version)
    result["Hadoop Version"] = version
  end
  if body:match("Hadoop%s+Compiled</td><td>([^][<]+)") then
    local compiled = body:match("Hadoop%s+Compiled</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Hadoop Compiled %s",compiled)
    result["Hadoop Compiled"] = compiled
  end
  if body:match("average</td><td>([^][<]+)") then
    local average = body:match("average</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Average Load %s",average)
    result["Average Load"] = average
  end
  if body:match("Quorum</td><td>([^][<]+)") then
    local quorum = body:match("Quorum</td><td>([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Zookeeper Quorum %s",quorum)
    result["Zookeeper Quorum"] = quorum
    if target.ALLOW_NEW_TARGETS then
      if quorum:match("([%w%.]+)") then
        local newtarget = quorum:match("([%w%.]+)")
        stdnse.debug1("Added target: %s", newtarget)
        local status,err = target.add(newtarget)
      end
    end
  end
  for line in string.gmatch(body, "[^\n]+") do
    stdnse.debug3("Line %s\n",line)
    if line:match("maxHeap") then
      local region_server=  line:match("\">([^][<]+)</a>")
      stdnse.debug1("Region Server %s",region_server)
      table.insert(region_servers, region_server)
      if target.ALLOW_NEW_TARGETS then
        if region_server:match("([%w%.]+)") then
          local newtarget = region_server:match("([%w%.]+)")
          stdnse.debug1("Added target: %s", newtarget)
          local status,err = target.add(newtarget)
        end
      end
    end
  end
  if next(region_servers) then
    result["Region Servers"] = region_servers
  end
  if #result > 0 then
    port.version.name = "hbase-master"
    port.version.product = "Apache Hadoop Hbase"
    nmap.set_port_version(host, port)
  end
  return result
end
