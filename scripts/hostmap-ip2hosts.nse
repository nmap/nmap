description = [[
Finds hostnames that resolve to the target's IP address by querying the online database:
* http://www.ip2hosts.com ( Bing Search Results )

The script is in the "external" category because it sends target IPs to a third party in order to query their database.
]]

---
-- @args hostmap.prefix If set, saves the output for each host in a file
-- called "<prefix><target>". The file contains one entry per line.
-- @args newtargets If set, add the new hostnames to the scanning queue.
-- This the names presumably resolve to the same IP address as the
-- original target, this is only useful for services such as HTTP that
-- can change their behavior based on hostname.
--
-- @usage
-- nmap --script hostmap-ip2hosts --script-args 'hostmap-ip2hosts.prefix=hostmap-' <targets>
-- @usage
-- nmap -sn --script hostmap-ip2hosts <target>
-- @output
-- Host script results:
-- | hostmap-ip2hosts: 
-- |   hosts: 
-- |     insecure.org
-- |     nmap.org
-- |     sectools.org
-- |     svn.nmap.org
-- |     cgi.insecure.org
-- |_  filename: output_nmap.org
-- @xmloutput
-- <table key="hosts">
--  <elem>insecure.org</elem>
--  <elem>nmap.org</elem>
--  <elem>sectools.org</elem>
--  <elem>svn.nmap.org</elem>
--  <elem>cgi.insecure.org</elem>
--  </table>
-- <elem key="filename">output_nmap.org</elem>
---

author = {'Paulino Calderon <calderon@websec.mx>'}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"external", "discovery"}

local dns = require "dns"
local ipOps = require "ipOps"
local http = require "http"
local stdnse = require "stdnse"
local target = require "target"

local HOSTMAP_BING_SERVER = "www.ip2hosts.com"
local HOSTMAP_DEFAULT_PROVIDER = "ALL"

local write_file

hostrule = function(host)
  return not ipOps.isPrivate(host.ip)
end

local function query_bing(ip) 
  local query = "/csv.php?ip=" .. ip
  local response
  local entries
  response = http.get(HOSTMAP_BING_SERVER, 80, query)
  local hostnames = {}
  if not response.status then
    return string.format("Error: could not GET http://%s%s", HOSTMAP_BING_SERVER, query)
  end
  entries = stdnse.strsplit(",", response.body);
  for _, entry in pairs(entries) do
    if not hostnames[entry] and entry ~= "" then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      entry = string.gsub(entry, "(https://)", "")
      entry = string.gsub(entry, "(http://)", "")
      hostnames[#hostnames + 1] = entry
    end
  end

  if #hostnames == 0 then
    if not string.find(response.body, "no results") then
      return "Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)"
    end
  end
  return hostnames
end

action = function(host)
  local filename_prefix = stdnse.get_script_args("hostmap.prefix")
  local hostnames = {}
  local hostnames_str, output_str 
  local output_tab = stdnse.output_table()
  stdnse.print_debug(1, "Using database: %s", HOSTMAP_BING_SERVER)
  hostnames = query_bing(host.ip)

  output_tab.hosts = hostnames
  --write to file
  if filename_prefix then
    local filename = filename_prefix .. stdnse.filename_escape(host.targetname or host.ip)
    hostnames_str = stdnse.strjoin("\n", hostnames)
    local status, err = write_file(filename, hostnames_str)
    if status then
      output_tab.filename = filename
    else
      stdnse.print_debug(1, "There was an error saving the file %s:%s", filename, err)
    end
  end

  return output_tab
end

function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end
