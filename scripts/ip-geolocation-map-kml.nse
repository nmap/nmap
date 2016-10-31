local http = require "http"
local geoip = require "geoip"
local io = require "io"
local stdnse = require "stdnse"
local table = require "table"

description = [[
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

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

local render = function(path)
  local kml = {}
  table.insert(kml, '<?xml version="1.0" encoding="UTF-8"?>')
  table.insert(kml, '<kml xmlns="http://www.opengis.net/kml/2.2">')
  table.insert(kml, '  <Document>')

  for ip, coords in pairs(geoip.get_all()) do
    table.insert(kml, "    <Placemark>")
    table.insert(kml, "      <name>" .. ip .. "</name>")
    table.insert(kml, "      <Point>")
    table.insert(kml, "        <coordinates>" .. coords["latitude"] .. "," .. coords["longitude"] .. "</coordinates>")
    table.insert(kml, "      </Point>")
    table.insert(kml, "    </Placemark>")
  end

  table.insert(kml, '  </Document>')
  table.insert(kml, '</kml>\n')

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
  return not geoip.empty()
end

action = function()
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, path = parse_args()
  if not status then
    output.ERROR = query
    return output, output.ERROR
  end

  -- Render the map.
  local status, msg = render(path)
  if not status then
    output.ERROR = msg
    return output, output.ERROR
  end

  return output, stdnse.format_output(true, msg)
end
