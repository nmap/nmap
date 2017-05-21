local http = require "http"
local io = require "io"
local json = require "json"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local ipOps = require "ipOps"

description = [[
Lists the geographic locations of each hop in a traceroute and optionally
saves the results to a KML file, plottable on Google earth and maps.
]]

---
-- @usage
-- nmap --traceroute --script traceroute-geolocation
--
-- @output
-- | traceroute-geolocation:
-- |   hop  RTT     ADDRESS                                               GEOLOCATION
-- |   1    ...
-- |   2    ...
-- |   3    ...
-- |   4    ...
-- |   5    16.76   e4-0.barleymow.stk.router.colt.net (194.68.128.104)   62,15 Sweden (Unknown)
-- |   6    48.61   te0-0-2-0-crs1.FRA.router.colt.net (212.74.65.49)     54,-2 United Kingdom (Unknown)
-- |   7    57.16   87.241.37.146                                         42,12 Italy (Unknown)
-- |   8    157.85  212.162.64.146                                        42,12 Italy (Unknown)
-- |   9    ...
-- |_  10   ...
-- @xmloutput
-- <table>
--   <elem key="hop">1</elem>
-- </table>
-- <table>
--   <elem key="hop">2</elem>
-- </table>
-- <table>
--   <elem key="hop">3</elem>
-- </table>
-- <table>
--   <elem key="hop">4</elem>
-- </table>
-- <table>
--   <elem key="hop">5</elem>
--   <elem key="rtt">16.76</elem>
--   <elem key="ip">194.68.128.104</elem>
--   <elem key="hostname">e4-0.barleymow.stk.router.colt.net</elem>
--   <elem key="lat">62</elem>
--   <elem key="lon">15</elem>
-- </table>
-- <table>
--   <elem key="hop">6</elem>
--   <elem key="rtt">48.61</elem>
--   <elem key="ip">212.74.65.49</elem>
--   <elem key="hostname">te0-0-2-0-crs1.FRA.router.colt.net</elem>
--   <elem key="lat">54</elem>
--   <elem key="lon">-2</elem>
-- </table>
--
-- @args traceroute-geolocation.kmlfile full path and name of file to write KML
--       data to. The KML file can be used in Google earth or maps to plot the
--       traceroute data.
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "external", "discovery"}

local arg_kmlfile = stdnse.get_script_args(SCRIPT_NAME .. ".kmlfile")

hostrule = function(host)
  if ( not(host.traceroute) ) then
    return false
  end
  return true
end

--
-- GeoPlugin requires no API key and has no limitations on lookups
--
local function geoLookup(ip, no_cache)
  local output = stdnse.registry_get({SCRIPT_NAME, ip})
  if output then return output end

  local response = http.get("www.geoplugin.net", 80, "/json.gp?ip="..ip, {any_af=true})
  local stat, loc = json.parse(response.body)

  if not stat then return nil end
  local regionName = (loc.geoplugin_regionName == json.NULL) and "Unknown" or loc.geoplugin_regionName
  output = {
    lat = loc.geoplugin_latitude,
    lon = loc.geoplugin_longitude,
    reg = regionName,
    ctry = loc.geoplugin_countryName
  }
  if not no_cache then
    stdnse.registry_add_table({SCRIPT_NAME}, ip, output)
  end
  return output
end

local function createKMLFile(filename, coords)
  local header = '<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://earth.google.com/kml/2.0"><Document><Placemark><LineString><coordinates>\r\n'
  local footer = '</coordinates></LineString><Style><LineStyle><color>#ff0000ff</color></LineStyle></Style></Placemark></Document></kml>'

  local output = {}
  for _, coord in ipairs(coords) do
    output[#output+1] = ("%s,%s, 0.\r\n"):format(coord.lon, coord.lat)
  end

  local f = io.open(filename, "w")
  if ( not(f) ) then
    return false, "Failed to create KML file"
  end
  f:write(header .. table.concat(output) .. footer)
  f:close()

  return true
end

-- Tables used to accumulate output.
local output_structured = {}
local output = tab.new(4)
local coordinates = {}

local function output_hop(count, ip, name, rtt, geo)
  if ip then
    local label
    if name then
      label = ("%s (%s)"):format(name or "", ip)
    else
      label = ("%s"):format(ip)
    end
    if geo then
      table.insert(output_structured, { hop = count, ip = ip, hostname = name, rtt = ("%.2f"):format(rtt), lat = geo.lat, lon = geo.lon })
      tab.addrow(output, count, ("%.2f"):format(rtt), label, ("%.3f,%.3f %s (%s)"):format(geo.lat, geo.lon, geo.ctry, geo.reg))
      table.insert(coordinates, { hop = count, lat = geo.lat, lon = geo.lon })
    else
      table.insert(output_structured, { hop = count, ip = ip, hostname = name, rtt = ("%.2f"):format(rtt) })
      tab.addrow(output, count, ("%.2f"):format(rtt), label, ("%s,%s"):format("- ", "- "))
    end
  else
    table.insert(output_structured, { hop = count })
    tab.addrow(output, count, "...")
  end
end

action = function(host)
  tab.addrow(output, "HOP", "RTT", "ADDRESS", "GEOLOCATION")
  for count = 1, #host.traceroute do
    local hop = host.traceroute[count]
    -- avoid timedout hops, marked as empty entries
    -- do not add the current scanned host.ip
    if hop.ip then
      local rtt = tonumber(hop.times.srtt) * 1000
      local geo
      if not ipOps.isPrivate(hop.ip) then
        -- be sure not to cache the target address, since it's not likely to be
        -- a hop for something else.
        geo = geoLookup(hop.ip, ipOps.compare_ip(hop.ip, "eq", host.ip) )
      end
      output_hop(count, hop.ip, hop.name, rtt, geo)
    else
      output_hop(count)
    end
  end

  if (#output_structured > 0) then
    output = tab.dump(output)
    if ( arg_kmlfile ) then
      if ( not(createKMLFile(arg_kmlfile, coordinates)) ) then
        output = output .. ("\n\nERROR: Failed to write KML to file: %s"):format(arg_kmlfile)
      end
    end
    return output_structured, stdnse.format_output(true, output)
  end
end
