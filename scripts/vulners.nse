description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
- work only when some software version is identified for an open port
- take all the known CPEs for that software (from the standard nmap -sV output)
- make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
 - if no info is found this way - try to get it using the software name alone
- print the obtained info out

NB:
Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db. 
So we do make requests to a remote service. Still all the requests contain just two fields - the 
software name and its version (or CPE), so one can still have the desired privacy.
]]

---
-- @usage 
-- nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>
--
-- @output
--
-- 53/tcp   open     domain             ISC BIND DNS
-- | vulners:
-- |   ISC BIND DNS:
-- |     CVE-2012-1667        8.5        https://vulners.com/cve/CVE-2012-1667
-- |     CVE-2002-0651        7.5        https://vulners.com/cve/CVE-2002-0651
-- |     CVE-2002-0029        7.5        https://vulners.com/cve/CVE-2002-0029
-- |     CVE-2015-5986        7.1        https://vulners.com/cve/CVE-2015-5986
-- |     CVE-2010-3615        5.0        https://vulners.com/cve/CVE-2010-3615
-- |     CVE-2006-0987        5.0        https://vulners.com/cve/CVE-2006-0987
-- |     CVE-2014-3214        5.0        https://vulners.com/cve/CVE-2014-3214
--

author = 'gmedian AT vulners DOT com'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}


local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"

local api_version="1.2"
local mincvss=nmap.registry.args.mincvss and tonumber(nmap.registry.args.mincvss) or 0.0


portrule = function(host, port)
    local vers=port.version
    return vers ~= nil and vers.version ~= nil
end


---
-- Return a string with all the found cve's and correspondent links
-- 
-- @param vulns a table with the parsed json response from the vulners server 
--
function make_links(vulns)
  local output_str=""
  local is_exploit=false
  local cvss_score=""

  -- NOTE[gmedian]: data.search is a "list" already, so just use table.sort with a custom compare function
  -- However, for the future it might be wiser to create a copy rather than do it in-place

  local vulns_result = {} 
  for _, v in ipairs(vulns.data.search) do
    table.insert(vulns_result, v)
  end

  -- Sort the acquired vulns by the CVSS score
  table.sort(vulns_result, function(a, b)
                              return a._source.cvss.score > b._source.cvss.score
                           end
  )

  for _, vuln in ipairs(vulns_result) do
    -- Mark the exploits out
    is_exploit = vuln._source.bulletinFamily:lower() == "exploit"

    -- Sometimes it might happen, so check the score availability
    cvss_score = vuln._source.cvss and (type(vuln._source.cvss.score) == "number") and (vuln._source.cvss.score) or ""

    -- NOTE[gmedian]: exploits seem to have cvss == 0, so print them anyway
    if is_exploit or (cvss_score ~= "" and mincvss <= tonumber(cvss_score)) then
      output_str = string.format("%s\n\t%s", output_str, vuln._source.id .. "\t\t" .. cvss_score .. '\t\thttps://vulners.com/' .. vuln._source.type .. '/' .. vuln._source.id .. (is_exploit and '\t\t*EXPLOIT*' or ''))
    end
  end
  
  return output_str
end


---
-- Issues the requests, receives json and parses it, calls <code>make_links</code> when successfull
--
-- @param what string, future value for the software query argument
-- @param vers string, the version query argument
-- @param type string, the type query argument
--
function get_results(what, vers, type)
  local v_host="vulners.com"
  local v_port=443 
  local response, path
  local status, error
  local vulns
  local option={header={}}

  option['header']['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)

  path = '/api/v3/burp/software/' .. '?software=' .. what .. '&version=' .. vers .. '&type=' .. type

  response = http.get(v_host, v_port, path, option)

  status = response.status
  if status == nil then
    -- Something went really wrong out there
    -- According to the NSE way we will die silently rather than spam user with error messages
    return ""
  elseif status ~= 200 then
    -- Again just die silently
    return ""
  end

  status, vulns = json.parse(response.body)

  if status == true then
    if vulns.result == "OK" then
      return make_links(vulns)
    end
  end

  return ""
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
  local vers
  local vers_regexp=":([%d%.%-%_]+)([^:]*)$"
  local output_str=""
  
  -- TODO[gmedian]: add check for cpe:/a  as we might be interested in software rather than in OS (cpe:/o) and hardware (cpe:/h)
  -- TODO[gmedian]: work not with the LAST part but simply with the THIRD one (according to cpe doc it must be version)

  -- NOTE[gmedian]: take only the numeric part of the version
  _, _, vers = cpe:find(vers_regexp)


  if not vers then
    return ""
  end

  output_str = get_results(cpe, vers, "cpe")

  if output_str == "" then
    local new_cpe

    new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
    output_str = get_results(new_cpe, vers, "cpe")
  end
  
  return output_str
end


action = function(host, port)
  local tab={}
  local changed=false
  local response
  local output_str=""

  for i, cpe in ipairs(port.version.cpe) do 
    output_str = get_vulns_by_cpe(cpe, port.version)
    if output_str ~= "" then
      tab[cpe] = output_str
      changed = true
    end
  end

  -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
  if not changed then
    local vendor_version = port.version.product .. " " .. port.version.version
    output_str = get_vulns_by_software(port.version.product, port.version.version)
    if output_str ~= "" then
      tab[vendor_version] = output_str
      changed = true
    end
  end
  
  if (not changed) then
    return
  end
  return tab
end

