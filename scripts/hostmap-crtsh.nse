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
-- @args hostmap.prefix  Save results to "<prefix><target>" with one hostname per line.
-- @args hostmap-crtsh.lax  Include hostname-like identities that are not strict subdomains.
-- @args newtargets  Add discovered hostnames as new scan targets (for virtual-host services).
---

-- TODO:
-- At the moment the script reports all hostname-like identities where
-- the parent hostname is present somewhere in the identity. Specifically,
-- the script does not verify that a returned identity is truly a subdomain
-- of the parent hostname. As an example, one of the returned identities for
-- "google.com" is "google.com.gr".
-- Since fixing it would change the script behavior that some users might
-- currently depend on then this should be discussed first. [nnposter]

author = {
  "Paulino Calderon <calderon@websec.mx>",
  "Sweekar-cmd",
}

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

local function get_hostname(host)
  return host.targetname or (host.name ~= '' and host.name) or nil
end

hostrule = get_hostname

local function is_valid_hostname(name)
  local labels = stringaux.strsplit("%.", name)
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

local function is_subdomain(name, suffix)
  return #name > #suffix and name:sub(-#suffix) == suffix
end

local function query_ctlogs(hostname, lax_mode)
  local hostname_lc = hostname:lower()
  local suffix = "." .. hostname_lc
  local parent = suffix:sub(2)

  local url = string.format("https://crt.sh/?q=%%.%s&output=json", parent)
  local response = http.get_url(url)
  if not (response.status == 200 and response.body) then
    stdnse.debug1("Error: Could not GET %s", url)
    return
  end

  local ok, data = json.parse(response.body)
  if not ok then
    stdnse.debug1("Error: Invalid JSON from %s", url)
    return
  end

  local results = {}

  for _, cert in ipairs(data) do
    local raw = cert.name_value
    if type(raw) == "string" then
      for _, name in ipairs(stringaux.strsplit("%s+", raw:lower())) do

        if name:find("*.", 1, true) == 1 then
          name = name:sub(3)
        end

        if name ~= hostname_lc
          and is_valid_hostname(name)
          and not results[name]
        then
          if lax_mode or is_subdomain(name, suffix) then
            results[name] = true
            if target.ALLOW_NEW_TARGETS then
              target.add(name)
            end
          end
        end

      end
    end
  end

  results = tableaux.keys(results)
  return (#results > 0) and results or nil
end

local function write_file(name, contents)
  local f, err = io.open(name, "w")
  if not f then return nil, err end
  f:write(contents)
  f:close()
  return true
end

action = function(host)
  local hostname = get_hostname(host)
  if not hostname then return end

  local lax = stdnse.get_script_args("hostmap-crtsh.lax")
  local lax_mode = (lax == true or lax == "true" or lax == "1")

  local prefix = stdnse.get_script_args("hostmap.prefix")
  local hostnames = query_ctlogs(hostname, lax_mode)
  if not hostnames then return end

  local out = stdnse.output_table()
  out.subdomains = hostnames

  if prefix then
    local filename = prefix .. stringaux.filename_escape(hostname)
    local list = table.concat(hostnames, "\n")
    local ok, err = write_file(filename, list)
    if ok then out.filename = filename
    else stdnse.debug1("Error saving %s: %s", filename, err)
    end
  end

  return out
end
