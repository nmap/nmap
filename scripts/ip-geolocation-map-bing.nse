local http = require "http"
local geoip = require "geoip"
local io = require "io"
local oops = require "oops"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
This script queries the Nmap registry for the GPS coordinates of targets stored
by previous geolocation scripts and renders a Bing Map of markers representing
the targets.

The Bing Maps REST API has a limit of 100 markers, so if more coordinates are
found, only the top 100 markers by number of IPs will be shown.

Additional information for the Bing Maps REST Services API can be found at:
- https://msdn.microsoft.com/en-us/library/ff701724.aspx
]]

---
-- @usage
-- nmap -sn -Pn --script ip-geolocation-geoplugin,ip-geolocation-map-bing --script-args ip-geolocation-map-bing.api_key=[redacted],ip-geolocation-map-bing.map_path=map.png <target>
--
-- @output
-- | ip-geolocation-map-bing:
-- |_  The map has been saved at 'map.png'.
--
-- @args ip-geolocation-map-bing.api_key The required Bing Maps API key for your
-- account. An API key can be generated at https://www.bingmapsportal.com/
--
-- @args ip-geolocation-map-bing.center GPS coordinates defining the center of the
-- image. If omitted, Bing Maps will choose a center that shows all the
-- markers.
--
-- @args ip-geolocation-map-bing.format The default value is 'jpeg', 'png', and
-- 'gif' are also allowed.
--
-- @args ip-geolocation-map-bing.language The default value is 'en', but other
-- two-letter language codes are accepted.
--
-- @args ip-geolocation-map-bing.layer The default value is 'Road',
-- 'Aerial', and 'AerialWithLabels' are also allowed.
--
-- @args ip-geolocation-map-bing.map_path The path at which the rendered
-- Bing Map will be saved to the local filesystem.
--
-- @args ip-geolocation-map-bing.marker_style This argument can apply styling
-- to the markers.
-- https://msdn.microsoft.com/en-us/library/ff701719.aspx
--
-- @args ip-geolocation-map-bing.size The default value is '640x640' pixels, but
-- can be changed so long as the width is between 80 and 2000 pixels and the
-- height is between 80 and 1500 pixels.
--
-- @see ip-geolocation-geoplugin.nse
-- @see ip-geolocation-ipinfodb.nse
-- @see ip-geolocation-map-google.nse
-- @see ip-geolocation-map-kml.nse
-- @see ip-geolocation-maxmind.nse

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

local render = function(params, options)
  -- Format marker style for inclusion in parameters.
  local style = ""
  if options["marker_style"] then
    style = ";" .. options["marker_style"]
  end

  -- Add in a marker for each host.
  local markers = {}
  for coords, ip in pairs(geoip.get_all_by_gps()) do
    table.insert(markers, {#ip, "pp=" .. coords .. style})
  end
  if #markers > 100 then
    -- API is limited to 100 markers
    stdnse.verbose1("Bing Maps API limits render to 100 markers. Some results not mapped.")
    -- sort by number of IPs so we map the biggest groups
    table.sort(markers, function (a, b) return a[1] < b[1] end)
  end
  local out_markers = {}
  for i=1, #markers do
    if i > 100 then break end
    out_markers[#out_markers+1] = markers[i][2]
  end
  local body = table.concat(out_markers, "&")

  -- Format the parameters into a properly encoded URL.
  local query = "/REST/v1/Imagery/Map/" .. options["layer"] .. "?" .. url.build_query(params)
  stdnse.debug1("The query URL is: %s", query)
  stdnse.debug1("The query body is: %s", body)

  local headers = {
    ["header"] = {
      ["Content-Type"] = "text/plain; charset=utf-8"
    }
  }

  local res = http.post("dev.virtualearth.net", 80, query, headers, nil, body)
  if not res or res.status ~= 200 then
    stdnse.debug1("Error %d from API: %s", res.status, res.body)
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

  local msg

  return true, ("The map has been saved at '%s'."):format(options["map_path"])
end

local parse_args = function()
  local options = {}
  local params = {}

  local api_key = stdnse.get_script_args(SCRIPT_NAME .. '.api_key')
  if not api_key then
    return false, "Need to specify an API key, get one at https://www.bingmapsportal.com/."
  end
  params["key"] = api_key

  local center = stdnse.get_script_args(SCRIPT_NAME .. ".center")
  if center then
    params["centerPoint"] = center
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
  if not layer then
    layer = "Road"
  end
  options["layer"] = layer

  local map_path = stdnse.get_script_args(SCRIPT_NAME .. '.map_path')
  if map_path then
    options["map_path"] = map_path
  else
    return false, "Need to specify a path for the map."
  end

  local size = stdnse.get_script_args(SCRIPT_NAME .. ".size")
  if not size then
    -- This size is arbitrary, and is chosen to match the default that Google
    -- Maps will produce.
    size = "640x640"
  end
  size = string.gsub(size, "x", ",")
  params["mapSize"] = size

  return true, params, options
end

postrule = function()
  -- Only run if a previous script has registered geolocation data.
  return not geoip.empty()
end

action = function()
  -- Parse and sanity check the command line arguments.
  local status, params, options = oops.raise(
    "Script argument problem",
    parse_args())
  if not status then
    return params
  end

  -- Render the map.
  return oops.output(render(params, options))
end
