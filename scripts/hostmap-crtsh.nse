description = [[
Finds subdomains of a web server by querying Google's Certificate Transparency
logs database (https://crt.sh).

The script will run against any target that has a name, either specified on the
command line or obtained via reverse-DNS.

NSE implementation of ctfr.py (https://github.com/UnaPibaGeek/ctfr.git) by Sheila Berta.

References:
* www.certificate-transparency.org
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
-- nmap --script hostmap-crtsh --script-args 'hostmap-crtsh.prefix=hostmap-' <targets>
-- @usage
-- nmap -sn --script hostmap-crtsh <target>
-- @output
-- Host script results:
-- | hostmap-crtsh:
-- |   subdomains:
-- |     svn.nmap.org
-- |     www.nmap.org
-- |_  filename: output_nmap.org
-- @xmloutput
-- <table key="subdomains">
--  <elem>svn.nmap.org</elem>
--  <elem>www.nmap.org</elem>
--  </table>
-- <elem key="filename">output_nmap.org</elem>
---

author = "Paulino Calderon <calderon@websec.mx>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"external", "discovery"}

local ipOps = require "ipOps"
local io = require "io"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local target = require "target"
local table = require "table"
local shortport = require "shortport"

-- Different from stdnse.get_hostname
-- this function returns nil if the host is only known by IP address
local function get_hostname (host)
  return host.targetname or (host.name ~= '' and host.name)
end

-- Run on any target that has a name
hostrule = get_hostname

local function query_ctlogs(host)
  local query = string.format("/?q=%%.%s&output=json", get_hostname(host))
  local response
  response = http.get("crt.sh", 443, query )
  local hostnames = {}
  if not response.status then
    return string.format("Error: could not GET http://%s%s", "crt.sh", query)
  end
  for domain in string.gmatch(response.body, "name_value\":\"(.-)\"") do
    if not stdnse.contains(hostnames, domain) and domain ~= "" then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(domain)
      end
      table.insert(hostnames, domain)
    end
  end

  if #hostnames<1 then
    if not string.find(response.body, "no results") then
      return "Error: found no hostnames but not the marker for \"name_value\" (pattern error?)"
    end
  end
  return hostnames
end

local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

action = function(host)
  local filename_prefix = stdnse.get_script_args("hostmap.prefix")
  local hostnames = {}
  local hostnames_str, output_str
  local output_tab = stdnse.output_table()
  hostnames = query_ctlogs(host)

  output_tab.subdomains = hostnames
  --write to file
  if filename_prefix then
    local filename = filename_prefix .. stdnse.filename_escape(get_hostname(host))
    hostnames_str = stdnse.strjoin("\n", hostnames)

    local status, err = write_file(filename, hostnames_str)
    if status then
      output_tab.filename = filename
    else
      stdnse.debug1("There was an error saving the file %s:%s", filename, err)
    end
  end

  return output_tab
end

