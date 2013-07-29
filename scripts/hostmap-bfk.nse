local dns = require "dns"
local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local target = require "target"

description = [[
Discovers hostnames that resolve to the target's IP address by querying the online database at http://www.bfk.de/bfk_dnslogger.html.

The script is in the "external" category because it sends target IPs to a third party in order to query their database.

This script was formerly (until April 2012) known as hostmap.nse.
]]

---
-- @args hostmap-bfk.prefix If set, saves the output for each host in a file
-- called "<prefix><target>". The file contains one entry per line.
-- @args newtargets If set, add the new hostnames to the scanning queue.
-- This the names presumably resolve to the same IP address as the
-- original target, this is only useful for services such as HTTP that
-- can change their behavior based on hostname.
--
-- @usage
-- nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- <targets>
--
-- @output
-- Host script results:
-- | hostmap-bfk: 
-- |   hosts: 
-- |     insecure.org
-- |     173.255.243.189
-- |     images.insecure.org
-- |     www.insecure.org
-- |     nmap.org
-- |     189.243.255.173.in-addr.arpa
-- |     mail.nmap.org
-- |     svn.nmap.org
-- |     www.nmap.org
-- |     sectools.org
-- |     seclists.org
-- |_    li253-189.members.linode.com
--
-- @xmloutput
-- <table key="hosts">
--  <elem>insecure.org</elem>
--  <elem>173.255.243.189</elem>
--  <elem>images.insecure.org</elem>
--  <elem>www.insecure.org</elem>
--  <elem>nmap.org</elem>
--  <elem>189.243.255.173.in-addr.arpa</elem>
--  <elem>mail.nmap.org</elem>
--  <elem>svn.nmap.org</elem>
--  <elem>www.nmap.org</elem>
--  <elem>sectools.org</elem>
--  <elem>seclists.org</elem>
--  <elem>li253-189.members.linode.com</elem>
-- </table>
---

author = "Ange Gutek"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "intrusive"}


local HOSTMAP_SERVER = "www.bfk.de"

local write_file

hostrule = function(host)
  return not ipOps.isPrivate(host.ip)
end

action = function(host)
  local query = "/bfk_dnslogger.html?query=" .. host.ip
  local response
  local output_tab = stdnse.output_table()
  response = http.get(HOSTMAP_SERVER, 80, query)
  if not response.status then
    stdnse.print_debug(1, "Error: could not GET http://%s%s", HOSTMAP_SERVER, query)
    return nil
  end
  local hostnames = {}
  local hosts_log = {}
  for entry in string.gmatch(response.body, "#result\" rel=\"nofollow\">(.-)</a></tt>") do
    if not hostnames[entry] then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      hostnames[entry] = true
      hosts_log[#hosts_log + 1] = entry
    end
  end

  if #hosts_log == 0 then
    if not string.find(response.body, "<p>The server returned no hits.</p>") then
      stdnse.print_debug(1,"Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)")
    end
    return nil
  end
  output_tab.hosts = hosts_log
  local hostnames_str = stdnse.strjoin("\n", hostnames)

  local filename_prefix = stdnse.get_script_args("hostmap-bfk.prefix")
  if filename_prefix then
    local filename = filename_prefix .. stdnse.filename_escape(host.targetname or host.ip)
    local status, err = write_file(filename, hostnames_str .. "\n")
    if status then
      output_tab.filename = filename
    else
      stdnse.print_debug(1,"Error saving to %s: %s\n", filename, err)
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
