local http = require "http"
local geoip = require "geoip"
local io = require "io"
local stdnse = require "stdnse"
local table = require "table"

description = [[
]]

---
-- @usage
-- nmap -sn -Pn --script ip-geolocation-geoplugin,ip-geolocation-map-google --script-args ip-geolocation-map-google.api_key=[redacted],ip-geolocation-map-google.map_path=map.png <target>
--
-- @output
-- | ip-geolocation-map-google:
-- |_  The map has been saved at 'nmap.png'.
--
-- @args ip-geolocation-map-google.api_key (REQUIRED)
-- @args ip-geolocation-map-google.center
-- @args ip-geolocation-map-google.format
-- @args ip-geolocation-map-google.language
-- @args ip-geolocation-map-google.layer
-- @args ip-geolocation-map-google.map_path (REQUIRED)
-- @args ip-geolocation-map-google.marker_style
-- @args ip-geolocation-map-google.scale
-- @args ip-geolocation-map-google.size

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "external", "safe"}

local render = function(query, path)
  local res = http.get("maps.googleapis.com", 80, query)
  if not res or res.status ~= 200 then
    return false, ("Failed to recieve map using query '%s'."):format(query)
  end

  local f = io.open(path, "w")
  if not f then
    return false, ("Failed to open file '%s'."):format(path)
  end

  if not f:write(res.body) then
    return false, ("Failed to write file '%s'."):format(path)
  end

  f:close()

  return true, ("The map has been saved at '%s'."):format(path)
end

local parse_args = function()
  local query = "/maps/api/staticmap?"

  local api_key = stdnse.get_script_args(SCRIPT_NAME .. '.api_key')
  if not api_key then
    return false, "Need to specify an API key, get one at https://developers.google.com/maps/documentation/static-maps/."
  end
  query = query .. "key=" .. api_key

  local center = stdnse.get_script_args(SCRIPT_NAME .. "center")
  if center then
    query = query .. "&center=" .. center
  end

  local format = stdnse.get_script_args(SCRIPT_NAME .. "format")
  if format then
    query = query .. "&format=" .. format
  end

  local language = stdnse.get_script_args(SCRIPT_NAME .. "language")
  if language then
    query = query .. "&language=" .. language
  end

  local layer = stdnse.get_script_args(SCRIPT_NAME .. "layer")
  if layer then
    query = query .. "&layer=" .. layer
  end

  local map_path = stdnse.get_script_args(SCRIPT_NAME .. '.map_path')
  if not map_path then
    return false, "Need to specify a path for the map."
  end

  local scale = stdnse.get_script_args(SCRIPT_NAME .. "scale")
  if scale then
    query = query .. "&scale=" .. scale
  end

  local size = stdnse.get_script_args(SCRIPT_NAME .. "size")
  if not size then
    size = "640x640"
  end
  query = query .. "&size=" .. size

  -- Add in a marker for each host.
  query = query .. "&markers="
  local marker_style = stdnse.get_script_args(SCRIPT_NAME .. "marker_style")
  if marker_style then
    query = query .. marker_style
  end

  for ip, coords in pairs(geoip.get_all()) do
    query = query .. "%7C" .. coords["latitude"] .. "," .. coords["longitude"]
  end

  -- Check that the query string is below the 8192 character limit after
  -- URL-encoding.

  return true, query, map_path
end

postrule = function()
  return not geoip.empty()
end

action = function()
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, query, path = parse_args()
  if not status then
    output.ERROR = query
    return output, output.ERROR
  end

  -- Render the map.
  local status, msg = render(query, path)
  if not status then
    output.ERROR = msg
    return output, output.ERROR
  end

  return output, stdnse.format_output(true, msg)
end
