local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local openssl = stdnse.silent_require "openssl"


-- Set your Shodan API key here to avoid typing it in every time:
local apiKey = ""

author = "Glenn Wilkinson <glenn@sensepost.com> (idea: Charl van der Walt <charl@sensepost.com>)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[
Queries Shodan API for given targets and produces similar output to
a -sV nmap scan. The ShodanAPI key can be set with the 'apikey' script
argument, or hardcoded in the .nse file itself. You can get a free key from
https://developer.shodan.io

N.B if you want this script to run completely passively make sure to
include the -sn -Pn -n flags.
]]

---
-- @usage
--  nmap --script shodan-api x.y.z.0/24 -sn -Pn -n --script-args 'shodan-api.outfile=potato.csv,shodan-api.apikey=SHODANAPIKEY'
--  nmap --script shodan-api --script-args 'shodan-api.target=x.y.z.a,shodan-api.apikey=SHODANAPIKEY'
--
-- @output
-- | shodan-api: Report for 2600:3c01::f03c:91ff:fe18:bb2f (scanme.nmap.org)
-- | PORT	PROTO	PRODUCT      VERSION
-- | 80   tcp   Apache httpd
-- | 3306 tcp   MySQL        5.5.40-0+wheezy1
-- | 22   tcp   OpenSSH      6.0p1 Debian 4+deb7u2
-- |_443  tcp
--
--@args shodan-api.outfile Write the results to the specified CSV file
--@args shodan-api.apikey Specify the ShodanAPI key. This can also be hardcoded in the nse file.
--@args shodan-api.target Specify a single target to be scanned.
--
--@xmloutput
-- <table key="hostnames">
--   <elem>scanme.nmap.org</elem>
-- </table>
-- <table key="ports">
--   <table>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">22</elem>
--   </table>
--   <table>
--     <elem key="version">2.4.7</elem>
--     <elem key="product">Apache httpd</elem>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">80</elem>
--   </table>
-- </table>

-- ToDo: * Have an option to complement non-banner scans with shodan data (e.g. -sS scan, but
--          grab service info from Shodan
--       * Have script arg to include extra host info. e.g. Coutry/city of IP, datetime of
--          scan, verbose port output (e.g. smb share info)
--       * Warn user if they haven't set -sn -Pn and -n (and will therefore actually scan the host
--       * Accept IP ranges via the script argument 'target' parameter


-- Begin
if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    apiKey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey") or apiKey,
    count = 0
  }
end
local registry = nmap.registry[SCRIPT_NAME]
local outFile = stdnse.get_script_args(SCRIPT_NAME .. ".outfile")
local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")

local function lookup_target (target)
  local response = http.get("api.shodan.io", 443, "/shodan/host/".. target .."?key=" .. registry.apiKey, {any_af = true})
  if response.status == 404 then
    stdnse.debug1("Host not found: %s", target)
    return nil
  elseif (response.status ~= 200) then
    stdnse.debug1("Bad response from Shodan for IP %s : %s", target, response.status)
    return nil
  end

  local stat, resp = json.parse(response.body)
  if not stat then
    stdnse.debug1("Error parsing Shodan response: %s", resp)
    return nil
  end

  return resp
end

local function format_output(resp)
  if resp.error then
    return resp.error
  end

  if resp.data then
    registry.count = registry.count + 1
    local out = { hostnames = resp.hostnames, ports = {} }
    local ports = out.ports
    local tab_out = tab.new()
    tab.addrow(tab_out, "PORT", "PROTO", "PRODUCT", "VERSION")

    for key, e in ipairs(resp.data) do
      ports[#ports+1] = {
        number = e.port,
        protocol = e.transport,
        product = e.product,
        version = e.version,
      }
      tab.addrow(tab_out, e.port, e.transport, e.product or "", e.version or "")
    end
    return out, tab.dump(tab_out)
  else
    return "Unable to query data"
  end
end

prerule = function ()
  if (outFile ~= nil) then
    local file = io.open(outFile, "w")
    io.output(file)
    io.write("IP,Port,Proto,Product,Version\n")
  end

  if registry.apiKey == "" then
    registry.apiKey = nil
  end

  if not registry.apiKey then
    stdnse.verbose1("Error: Please specify your ShodanAPI key with the %s.apikey argument", SCRIPT_NAME)
    return false
  end

  local response = http.get("api.shodan.io", 443, "/api-info?key=" .. registry.apiKey, {any_af=true})
  if (response.status ~= 200) then
    stdnse.verbose1("Error: Your ShodanAPI key (%s) is invalid", registry.apiKey)
    -- Prevent further stages from running
    registry.apiKey = nil
    return false
  end

  if arg_target then
    local is_ip, err = ipOps.expand_ip(arg_target)
    if not is_ip then
      stdnse.verbose1("Error: %s.target must be an IP address", SCRIPT_NAME)
      return false
    end
    return true
  end
end

generic_action = function(ip)
  local resp = lookup_target(ip)
  if not resp then return nil end
  local out, tabular = format_output(resp)
  if type(out) == "string" then
    -- some kind of error
    return out
  end
  local result = string.format(
    "Report for %s (%s)\n%s",
    ip,
    table.concat(out.hostnames, ", "),
    tabular
    )
  if (outFile ~= nil) then
    for _, port in ipairs(out.ports) do
      io.write( string.format("%s,%s,%s,%s,%s\n",
          ip, port.number, port.protocol, port.product or "", port.version or "")
        )
    end
  end
  return out, result
end

preaction = function()
  return generic_action(arg_target)
end

hostrule = function(host)
  return registry.apiKey and not ipOps.isPrivate(host.ip)
end

hostaction = function(host)
  return generic_action(host.ip)
end

postrule = function ()
  return registry.apiKey
end

postaction = function ()
  local out = { "Shodan done: ", registry.count, " hosts up." }
  if outFile then
    io.close()
    out[#out+1] = "\nWrote Shodan output to: "
    out[#out+1] = outFile
  end
  return table.concat(out)
end

local ActionsTable = {
  -- prerule: scan target from script-args
  prerule = preaction,
  -- hostrule: look up a host in Shodan
  hostrule = hostaction,
  -- postrule: report results
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
