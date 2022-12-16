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

-- TODO:
-- At the moment the script reports all hostname-like identities where
-- the parent hostname is present somewhere in the identity. Specifically,
-- the script does not verify that a returned identity is truly a subdomain
-- of the parent hostname. As an example, one of the returned identities for
-- "google.com" is "google.com.gr".
-- Since fixing it would change the script behavior that some users might
-- currently depend on then this should be discussed first. [nnposter]

author = "Paulino Calderon <calderon@websec.mx>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"external", "discovery"}

local io = require "io"
local http = require "http"
local json = require "json"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local target = require "target"
local table = require "table"
local tableaux = require "tableaux"

-- Different from stdnse.get_hostname
-- this function returns nil if the host is only known by IP address
local function get_hostname (host)
  return host.targetname or (host.name ~= '' and host.name) or nil
end

-- Run on any target that has a name
hostrule = get_hostname

local function is_valid_hostname (name)
  local labels = stringaux.strsplit("%.", name)
  -- DNS name cannot be longer than 253
  -- do not accept TLDs; at least second-level domain required
  -- TLD cannot be all digits
  if #name > 253 or #labels < 2 or labels[#labels]:find("^%d+$") then
    return false
  end
  for _, label in ipairs(labels) do
    if not (#label <= 63 and label:find("^[%w_][%w_-]*%f[-\0]$")) then
      return false
    end
  end
  return true
end

local function query_ctlogs(hostname)
  local url = string.format("https://crt.sh/?q=%%.%s&output=json", hostname)
  local response = http.get_url(url)
  if not (response.status == 200 and response.body) then
    stdnse.debug1("Error: Could not GET %s", url)
    return
  end
  local jstatus, jresp = json.parse(response.body)
  if not jstatus then
    stdnse.debug1("Error: Invalid response from %s", url)
    return
  end
  local hostnames = {}
  for _, cert in ipairs(jresp) do
    local names = cert.name_value;
    if type(names) == "string" then
      for _, name in ipairs(stringaux.strsplit("%s+", names:lower())) do
        -- if this is a wildcard name, just proceed with the static portion
        if name:find("*.", 1, true) == 1 then
          name = name:sub(3)
        end
        if name ~= hostname and not hostnames[name] and is_valid_hostname(name) then
          hostnames[name] = true
          if target.ALLOW_NEW_TARGETS then
            target.add(name)
          end
        end
      end
    end
  end

  hostnames = tableaux.keys(hostnames)
  return #hostnames > 0 and hostnames or nil
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
  local hostname = get_hostname(host)
  local hostnames = query_ctlogs(hostname)
  if not hostnames then return end

  local output_tab = stdnse.output_table()
  output_tab.subdomains = hostnames
  --write to file
  if filename_prefix then
    local filename = filename_prefix .. stringaux.filename_escape(hostname)
    local hostnames_str = table.concat(hostnames, "\n")

    local status, err = write_file(filename, hostnames_str)
    if status then
      output_tab.filename = filename
    else
      stdnse.debug1("Error saving file %s: %s", filename, err)
    end
  end

  return output_tab
end
