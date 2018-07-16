local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Retrieves information from an Apache Hadoop JobTracker HTTP status page.

Information gathered:
* State of the JobTracker.
* Date/time the service was started
* Hadoop version
* Hadoop Compile date
* JobTracker ID
* Log directory (relative to http://host:port/)
* Associated TaskTrackers
* Optionally also user activity history
]]

---
-- @usage
-- nmap --script hadoop-jobtracker-info [--script-args=hadoop-jobtracker-info.userinfo] -p 50030 host
--
-- @args hadoop-jobtracker-info.userinfo Retrieve user history info. Default: false
--
-- @output
-- 50030/tcp open  hadoop-jobtracker
-- | hadoop-jobtracker-info:
-- |   State: RUNNING
-- |   Started: Wed May 11 22:33:44 PDT 2011, bob
-- |   Version: 0.20.2 (f415ef415ef415ef415ef415ef415ef415ef415e)
-- |   Compiled: Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Identifier: 201111031342
-- |   Log Files: logs/
-- |   Tasktrackers:
-- |     tracker1.example.com:50060
-- |     tracker2.example.com:50060
-- |   Userhistory:
-- |     User: bob (Wed Sep 07 12:14:33 CEST 2011)
-- |_    User: bob (Wed Sep 07 12:14:33 CEST 2011)
--
-- @xmloutput
-- <elem key="State">RUNNING</elem>
-- <elem key="Started">Wed May 11 22:33:44 PDT 2011, bob</elem>
-- <elem key="Version">0.20.2 (f415ef415ef415ef415ef415ef415ef415ef415e)</elem>
-- <elem key="Compiled">Wed May 11 22:33:44 PDT 2011 by bob from unknown</elem>
-- <elem key="Identifier">201111031342</elem>
-- <elem key="Log Files">logs/</elem>
-- <table key="Tasktrackers">
--   <elem>tracker1.example.com:50060</elem>
--   <elem>tracker2.example.com:50060</elem>
-- </table>
-- <table key="Userhistory">
--   <elem>User: bob (Wed Sep 07 12:14:33 CEST 2011)</elem>
--   <elem>User: bob (Wed Sep 07 12:14:33 CEST 2011)</elem>
-- </table>


author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  -- Run for the special port number, or for any HTTP-like service that is
  -- not on a usual HTTP port.
  return shortport.port_or_service ({50030}, "hadoop-jobtracker")(host, port)
    or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

local get_userhistory = function( host, port )
  local results = {}
  local uri = "/jobhistory.jsp?pageno=-1&search="
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
    local body = response['body']:gsub("%%","%%%%")
    stdnse.debug2("Body %s\n",body)
    for line in string.gmatch(body, "[^\n]+") do
      stdnse.debug3("Line %s\n",line)
      if line:match("job_[%d_]+") then
        local user =  line:match("<td>([^][<>]+)</td></tr>")
        local job_time =  line:match("</td><td>([^][<]+)")
        stdnse.debug1("User: %s (%s)",user,job_time)
        table.insert( results,  ("User: %s (%s)"):format(user,job_time))
      end
    end
  end
  if #results > 0 then
    return results
  end
end
local get_tasktrackers = function( host, port )
  local results = {}
  local uri = "/machines.jsp?type=active"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
    stdnse.debug2("Body %s\n",response['body'])
    for line in string.gmatch(response['body'], "[^\n]+") do
      stdnse.debug3("Line %s\n",line)
      if line:match("href=\"[%w]+://([%w%.:]+)/\">tracker") then
        local tasktracker =  line:match("href=\".*//([%w%.:]+)/\">tracker")
        stdnse.debug1("taskstracker %s",tasktracker)
        table.insert( results, tasktracker)
        if target.ALLOW_NEW_TARGETS then
          if tasktracker:match("([%w%.]+)") then
            local newtarget = tasktracker:match("([%w%.]+)")
            stdnse.debug1("Added target: %s", newtarget)
            local status,err = target.add(newtarget)
          end
        end
      end
    end
  end
  return results
end
action = function( host, port )

  local result = stdnse.output_table()
  local uri = "/jobtracker.jsp"
  stdnse.debug1("HTTP GET %s:%s%s", host.targetname or host.ip, port.number, uri)
  local response = http.get( host, port, uri )
  stdnse.debug1("Status %s",response['status-line'] or "No Response")
  if not (response['status-line'] and response['status-line']:match("200%s+OK") and response['body']) then
    return nil
  end
  stdnse.debug2("Body %s\n",response['body'])
  if response['body']:match("State:</b>%s*([^][<]+)") then
    local state = response['body']:match("State:</b>%s*([^][<]+)")
    stdnse.debug1("State %s",state)
    result["State"] = state
  end
  if response['body']:match("Started:</b>%s*([^][<]+)") then
    local started = response['body']:match("Started:</b>%s*([^][<]+)")
    stdnse.debug1("Started %s",started)
    result["Started"] = started
  end
  if response['body']:match("Version:</b>%s*([^][<]+)") then
    local version = response['body']:match("Version:</b>%s*([^][<]+)")
    local versionNo = version:match("([^][,]+)")
    local versionHash = version:match("[^][,]+%s+(%w+)")
    stdnse.debug1("Version %s (%s)",versionNo,versionHash)
    result["Version"] = ("%s (%s)"):format(versionNo,versionHash)
    port.version.version = versionNo
  end
  if response['body']:match("Compiled:</b>%s*([^][<]+)") then
    local compiled = response['body']:match("Compiled:</b>%s*([^][<]+)"):gsub("%s+", " ")
    stdnse.debug1("Compiled %s",compiled)
    result["Compiled"] = compiled
  end
  if response['body']:match("Identifier:</b>%s*([^][<]+)") then
    local identifier = response['body']:match("Identifier:</b>%s*([^][<]+)")
    stdnse.debug1("Identifier %s",identifier)
    result["Identifier"] = identifier
  end
  if response['body']:match("([%w/]+)\">Log<") then
    local logfiles = response['body']:match("([%w/-_:%%]+)\">Log<")
    stdnse.debug1("Log Files %s",logfiles)
    result["Log Files"] = logfiles
  end
  local tasktrackers = get_tasktrackers (host, port)
  if next(tasktrackers) then
    result["Tasktrackers"] = tasktrackers
  end
  if stdnse.get_script_args('hadoop-jobtracker-info.userinfo') then
    local userhistory = get_userhistory (host, port)
    result["Userhistory"] = userhistory
  end
  if #result > 0 then
    port.version.name = "hadoop-jobtracker"
    port.version.product = "Apache Hadoop"
    nmap.set_port_version(host, port)
    return result
  end
end
