local http = require "http"
local geoip = require "geoip"
local io = require "io"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

description = [[
This script queries the Nmap registry for the GPS coordinates of targets stored
by previous geolocation scripts and renders a Google Map of markers representing
the targets.

Additional information for the Google Static Maps API can be found at:
- https://developers.google.com/maps/documentation/static-maps/intro
]]

---
-- @usage
-- nmap -sn -Pn --script ip-geolocation-geoplugin,ip-geolocation-map-google --script-args ip-geolocation-map-google.api_key=[redacted],ip-geolocation-map-google.map_path=map.png <target>
--
-- @output
-- | ip-geolocation-map-google:
-- |_  The map has been saved at 'map.png'.
--
-- @args ip-geolocation-map-google.api_key The required Google Maps API key for
-- your account. An API key can be generated at
-- https://developers.google.com/maps/documentation/static-maps/
--
-- @args ip-geolocation-map-google.center GPS coordinates defining the center of the
-- image. If omitted, Google Maps will choose a center that shows all the
-- markers.
--
-- @args ip-geolocation-map-google.format The default value is 'png' (alias for
-- 'png8'), 'png32', 'gif', 'jpg', and 'jpg-baseline' are also allowed.
-- https://developers.google.com/maps/documentation/static-maps/intro#ImageFormats
--
-- @args ip-geolocation-map-google.language The default value is 'en', but other
-- two-letter language codes are accepted.
--
-- @args ip-geolocation-map-google.layer The default value is 'roadmap',
-- 'satellite', 'hybrid', and 'terrain' are also allowed.
-- https://developers.google.com/maps/documentation/static-maps/intro#MapTypes
--
-- @args ip-geolocation-map-google.map_path The path at which the rendered
-- Google Map will be saved to the local filesystem.
--
-- @args ip-geolocation-map-google.marker_style This argument can apply styling
-- to the markers.
-- https://developers.google.com/maps/documentation/static-maps/intro#MarkerStyles
--
-- @args ip-geolocation-map-google.scale The default value is 1, but values 2
-- and 4 are permitted. Scale level 4 is only available to Google Maps Premium
-- customers.
-- https://developers.google.com/maps/documentation/static-maps/intro#scale_values
--
-- @args ip-geolocation-map-google.size The default value is '640x640' pixels,
-- but can be increased by Google Maps Premium customers.
-- https://developers.google.com/maps/documentation/static-maps/intro#Imagesizes
--
-- @see ip-geolocation-geoplugin.nse
-- @see ip-geolocation-ipinfodb.nse
-- @see ip-geolocation-map-bing.nse
-- @see ip-geolocation-map-kml.nse
-- @see ip-geolocation-maxmind.nse

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

local render = function(params, options)
  -- Add in a marker for each GPS coordinate.
  local markers = {}
  for coords, ips in pairs(geoip.get_all_by_gps()) do
    table.insert(markers, coords)
  end
  params["markers"] = options["marker_style"] .. "|" .. table.concat(markers, "|")

  -- Format the parameters into a properly encoded URL.
  local query = "/maps/api/staticmap?" .. url.build_query(params)
  stdnse.debug1("The query URL is: %s", query)

  -- Check that the query string is below the 8192 character limit after
  -- URL-encoding.
  if #query > 8192 then
    return false, ("Refused to send query since URL path is %d chararacters, but Google Maps limits to 8192."):format(#query)
  end

  local res = http.get("maps.googleapis.com", 80, query)
  if not res or res.status ~= 200 then
    return false, ("Failed to receive map using query '%s'."):format(query)
  end

  local f = io.open(options["map_path"], "w")
  if not f then
    return false, ("Failed to open file '%s'."):format(options["map_path"])
  end

  if not f:write(res.body) then
    return false, ("Failed to write file '%s'."):format(options["map_path"])
  end

  f:close()

  return true, ("The map has been saved at '%s'."):format(options["map_path"])
end

local parse_args = function()
  local options = {}
  local params = {}

  local api_key = stdnse.get_script_args(SCRIPT_NAME .. '.api_key')
  if not api_key then
    return false, "Need to specify an API key, get one at https://developers.google.com/maps/documentation/static-maps/."
  end
  params["key"] = api_key

  local center = stdnse.get_script_args(SCRIPT_NAME .. ".center")
  if center then
    params["center"] = center
  end

  local format = stdnse.get_script_args(SCRIPT_NAME .. ".format")
  if format then
    params["format"] = format
  end

  local language = stdnse.get_script_args(SCRIPT_NAME .. ".language")
  if language then
    params["language"] = language
  end

  local layer = stdnse.get_script_args(SCRIPT_NAME .. ".layer")
  if layer then
    params["layer"] = layer
  end

  local map_path = stdnse.get_script_args(SCRIPT_NAME .. '.map_path')
  if map_path then
    options["map_path"] = map_path
  else
    return false, "Need to specify a path for the map."
  end

  local marker_style = stdnse.get_script_args(SCRIPT_NAME .. ".marker_style")
  if not marker_style then
    marker_style = ""
  end
  options["marker_style"] = marker_style

  local scale = stdnse.get_script_args(SCRIPT_NAME .. ".scale")
  if scale then
    params["scale"] = scale
  end

  local size = stdnse.get_script_args(SCRIPT_NAME .. ".size")
  if not size then
    size = "640x640"
  end
  params["size"] = size

  return true, params, options
end

postrule = function()
  -- Only run if a previous script has registered geolocation data.
  return not geoip.empty()
end

action = function()
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, params, options = parse_args()
  if not status then
    output.ERROR = params
    return output, output.ERROR
  end

  -- Render the map.
  local status, msg = render(params, options)
  if not status then
    output.ERROR = msg
    return output, output.ERROR
  end

  return output, stdnse.format_output(true, msg)
end
