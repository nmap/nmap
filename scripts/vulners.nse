description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

NB:
Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db.
So we do make requests to a remote service. Still all the requests contain just two fields - the
software name and its version (or CPE), so one can still have the desired privacy.
]]

---
-- @usage
-- nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>
--
-- @args vulners.mincvss Limit CVEs shown to those with this CVSS score or greater.
--
-- @output
--
-- 53/tcp   open     domain             ISC BIND DNS
-- | vulners:
-- |   ISC BIND DNS:
-- |     CVE-2012-1667    8.5    https://vulners.com/cve/CVE-2012-1667
-- |     CVE-2002-0651    7.5    https://vulners.com/cve/CVE-2002-0651
-- |     CVE-2002-0029    7.5    https://vulners.com/cve/CVE-2002-0029
-- |     CVE-2015-5986    7.1    https://vulners.com/cve/CVE-2015-5986
-- |     CVE-2010-3615    5.0    https://vulners.com/cve/CVE-2010-3615
-- |     CVE-2006-0987    5.0    https://vulners.com/cve/CVE-2006-0987
-- |_    CVE-2014-3214    5.0    https://vulners.com/cve/CVE-2014-3214
--
-- @xmloutput
-- <table key="cpe:/a:isc:bind:9.8.2rc1">
--   <table>
--     <elem key="is_exploit">false</elem>
--     <elem key="cvss">8.5</elem>
--     <elem key="id">CVE-2012-1667</elem>
--     <elem key="type">cve</elem>
--   </table>
--   <table>
--     <elem key="is_exploit">false</elem>
--     <elem key="cvss">7.8</elem>
--     <elem key="id">CVE-2015-4620</elem>
--     <elem key="type">cve</elem>
--   </table>
-- </table>

author = 'gmedian AT vulners DOT com'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}


local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"

local api_version="1.2"
local mincvss=stdnse.get_script_args("vulners.mincvss")
mincvss = tonumber(mincvss) or 0.0

portrule = function(host, port)
  local vers=port.version
  return vers ~= nil and vers.version ~= nil
end

local cve_meta = {
  __tostring = function(me)
      return ("\t%s\t%s\thttps://vulners.com/%s/%s%s"):format(me.id, me.cvss or "", me.type, me.id, me.is_exploit and '\t*EXPLOIT*' or '')
  end,
}

---
-- Return a string with all the found cve's and correspondent links
--
-- @param vulns a table with the parsed json response from the vulners server
--
function make_links(vulns)
  local output = {}

  if not vulns or not vulns.data or not vulns.data.search then
    return
  end

  for _, vuln in ipairs(vulns.data.search) do
    local v = {
      id = vuln._source.id,
      type = vuln._source.type,
      -- Mark the exploits out
      is_exploit = vuln._source.bulletinFamily:lower() == "exploit",
      -- Sometimes it might happen, so check the score availability
      cvss = tonumber(vuln._source.cvss.score),
    }

    -- NOTE[gmedian]: exploits seem to have cvss == 0, so print them anyway
    if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
      setmetatable(v, cve_meta)
      output[#output+1] = v
    end
  end

  if #output > 0 then
    -- Sort the acquired vulns by the CVSS score
    table.sort(output, function(a, b)
        return a.cvss > b.cvss or (a.cvss == b.cvss and a.id > b.id)
      end)
    return output
  end
end


---
-- Issues the requests, receives json and parses it, calls <code>make_links</code> when successfull
--
-- @param what string, future value for the software query argument
-- @param vers string, the version query argument
-- @param type string, the type query argument
--
function get_results(what, vers, type)
  local api_endpoint = "https://vulners.com/api/v3/burp/software/"
  local vulns
  local option={
    header={
      ['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)
    },
    any_af = true,
  }

  local response = http.get_url(('%s?software=%s&version=%s&type=%s'):format(api_endpoint, what, vers, type), option)

  local status = response.status
  if status == nil then
    -- Something went really wrong out there
    -- According to the NSE way we will die silently rather than spam user with error messages
    return
  elseif status ~= 200 then
    -- Again just die silently
    return
  end

  status, vulns = json.parse(response.body)

  if status == true then
    if vulns.result == "OK" then
      return make_links(vulns)
    end
  end
end


---
-- Calls <code>get_results</code> for type="software"
--
-- It is called from <code>action</code> when nothing is found for the available cpe's
--
-- @param software string, the software name
-- @param version string, the software version
--
function get_vulns_by_software(software, version)
  return get_results(software, version, "software")
end


---
-- Calls <code>get_results</code> for type="cpe"
--
-- Takes the version number from the given <code>cpe</code> and tries to get the result.
-- If none found, changes the given <code>cpe</code> a bit in order to possibly separate version number from the patch version
-- And makes another attempt.
-- Having failed returns an empty string.
--
-- @param cpe string, the given cpe
--
function get_vulns_by_cpe(cpe)
  local vers_regexp=":([%d%.%-%_]+)([^:]*)$"

  -- TODO[gmedian]: add check for cpe:/a  as we might be interested in software rather than in OS (cpe:/o) and hardware (cpe:/h)
  -- TODO[gmedian]: work not with the LAST part but simply with the THIRD one (according to cpe doc it must be version)

  -- NOTE[gmedian]: take only the numeric part of the version
  local _, _, vers = cpe:find(vers_regexp)


  if not vers then
    return
  end

  local output = get_results(cpe, vers, "cpe")

  if not output then
    local new_cpe

    new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
    output = get_results(new_cpe, vers, "cpe")
  end

  return output
end


action = function(host, port)
  local tab=stdnse.output_table()
  local changed=false
  local response
  local output

  for i, cpe in ipairs(port.version.cpe) do
    output = get_vulns_by_cpe(cpe, port.version)
    if output then
      tab[cpe] = output
      changed = true
    end
  end

  -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
  if not changed then
    local vendor_version = port.version.product .. " " .. port.version.version
    output = get_vulns_by_software(port.version.product, port.version.version)
    if output then
      tab[vendor_version] = output
      changed = true
    end
  end

  if (not changed) then
    return
  end
  return tab
end

