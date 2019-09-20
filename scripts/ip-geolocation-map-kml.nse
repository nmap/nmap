local geoip = require "geoip"
local io = require "io"
local oops = require "oops"
local stdnse = require "stdnse"
local table = require "table"

description = [[
This script queries the Nmap registry for the GPS coordinates of targets stored
by previous geolocation scripts and produces a KML file of points representing
the targets.
]]

---
-- @usage
-- nmap -sn -Pn --script ip-geolocation-geoplugin,ip-geolocation-map-kml --script-args ip-geolocation-map-kml.map_path=map.kml <target>
--
-- @output
-- | ip-geolocation-map-kml:
-- |_  The map has been saved at 'map.kml'.
--
-- @args ip-geolocation-map-kml.map_path (REQUIRED)
--
-- @see ip-geolocation-geoplugin.nse
-- @see ip-geolocation-ipinfodb.nse
-- @see ip-geolocation-map-bing.nse
-- @see ip-geolocation-map-google.nse
-- @see ip-geolocation-maxmind.nse

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

local render = function(path)
  local kml = {'<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n  <Document>'}

  for ip, coords in pairs(geoip.get_all_by_ip()) do
    table.insert(kml, ([[
    <Placemark>
      <name>%s</name>
      <Point>
        <coordinates>%s,%s</coordinates>
      </Point>
    </Placemark>]]):format(ip, coords["longitude"], coords["latitude"])
    )
  end

  table.insert(kml, '  </Document>\n</kml>\n')

  kml = table.concat(kml, "\n")

  local f = io.open(path, "w")
  if not f then
    return false, ("Failed to open file '%s'."):format(path)
  end

  if not f:write(kml) then
    return false, ("Failed to write file '%s'."):format(path)
  end

  f:close()

  return true, ("The map has been saved at '%s'."):format(path)
end

local parse_args = function()
  local map_path = stdnse.get_script_args(SCRIPT_NAME .. '.map_path')
  if not map_path then
    return false, "Need to specify a path for the map."
  end

  return true, map_path
end

postrule = function()
  -- Only run if a previous script has registered geolocation data.
  return not geoip.empty()
end

action = function()
  -- Parse and sanity check the command line arguments.
  local status, path = oops.raise(
    "Script argument problem",
    parse_args())
  if not status then
    return path
  end

  -- Render the map.
  return oops.output(render(path))
end
