local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache Hadoop secondary NameNode HTTP status page.

Information gathered:
 * Date/time the service was started
 * Hadoop version
 * Hadoop compile date
 * Hostname or IP address and port of the master NameNode server
 * Last time a checkpoint was taken
 * How often checkpoints are taken (in seconds)
 * Log directory (relative to http://host:port/)
 * File size of current checkpoint

For more information about Hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
 * http://wiki.apache.org/hadoop/NameNode
]]

---
-- @usage
-- nmap --script  hadoop-secondary-namenode-info -p 50090 host
--
-- @output
-- PORT      STATE  SERVICE REASON
-- 50090/tcp open   unknown syn-ack
-- | hadoop-secondary-namenode-info:
-- |   Start: Wed May 11 22:33:44 PDT 2011
-- |   Version: 0.20.2, f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Log: /logs/
-- |   namenode: namenode1.example.com/192.0.1.1:8020
-- |   Last Checkpoint: Wed May 11 22:33:44 PDT 2011
-- |   Checkpoint Period: 3600 seconds
-- |_  Checkpoint Size: 12345678 MB
--

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({50090}, "hadoop-secondary-namenode")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

action = function( host, port )

  local result = {}
  local uri = "/status.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Resposne")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
    local body = response['body']:gsub("%%","%%%%")
    local stats = {}
    stdnse.debug2("Body %s\n",body)
    -- Page isn't valid html :(
    for i in string.gmatch(body,"\n[%w%s]+:%s+[^][\n]+") do
      table.insert(stats,i:match(":%s+([^][\n]+)"))
    end
    if #stats == 5 then
      stdnse.debug1("namenode %s",stats[1])
      stdnse.debug1("Start %s",stats[2])
      stdnse.debug1("Last Checkpoint %s",stats[3])
      stdnse.debug1("Checkpoint Period %s",stats[4])
      stdnse.debug1("Checkpoint Size %s",stats[5])
      table.insert(result, ("Start: %s"):format(stats[2]))
    end
    if body:match("Version:%s*</td><td>([^][\n]+)") then
      local version = body:match("Version:%s*</td><td>([^][\n]+)")
      stdnse.debug1("Version %s",version)
      table.insert(result, ("Version: %s"):format(version))
      port.version.version = version
    end
    if body:match("Compiled:%s*</td><td>([^][\n]+)") then
      local compiled = body:match("Compiled:%s*</td><td>([^][\n]+)")
      stdnse.debug1("Compiled %s",compiled)
      table.insert(result, ("Compiled: %s"):format(compiled))
    end
    if body:match("([^][\"]+)\">Logs") then
      local logs = body:match("([^][\"]+)\">Logs")
      stdnse.debug1("Logs %s",logs)
      table.insert(result, ("Logs: %s"):format(logs))
    end
    if #stats == 5 then
      table.insert(result, ("Namenode: %s"):format(stats[1]))
      table.insert(result, ("Last Checkpoint: %s"):format(stats[3]))
      table.insert(result, ("Checkpoint Period: %s"):format(stats[4]))
      table.insert(result, ("Checkpoint: Size %s"):format(stats[5]))
    end
    if #result > 0 then
      port.version.name = "hadoop-secondary-namenode"
      port.version.product = "Apache Hadoop"
      nmap.set_port_version(host, port)
    end
    if target.ALLOW_NEW_TARGETS then
      if stats[1]:match("([^][/]+)") then
        local newtarget = stats[1]:match("([^][/]+)")
        stdnse.debug1("Added target: %s", newtarget)
        local status,err = target.add(newtarget)
      end
    end

  end
  return stdnse.format_output(true, result)
end
