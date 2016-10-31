local http = require "http"
local geoip = require "geoip"
local io = require "io"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

description = [[
This script queries the Nmap registry for the GPS coordinates of targets stored
by previous geolocation scripts and renders a Bing Map of markers representing
the targets.

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
-- @args ip-geolocation-map-bing.api_key (REQUIRED)
--
-- @args ip-geolocation-map-bing.center
--
-- @args ip-geolocation-map-bing.format
--
-- @args ip-geolocation-map-bing.language
--
-- @args ip-geolocation-map-bing.layer
--
-- @args ip-geolocation-map-bing.map_path (REQUIRED)
--
-- @args ip-geolocation-map-bing.marker_style
-- https://msdn.microsoft.com/en-us/library/ff701719.aspx
--
-- @args ip-geolocation-map-bing.scale
--
-- @args ip-geolocation-map-bing.size

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
  for coords, ip in pairs(geoip.get_all_by_gps(100)) do
    table.insert(markers, "pp=" .. coords .. style)
  end
  local body = table.concat(markers, "&")

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
    return false, ("Failed to recieve map using query '%s'."):format(query)
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
    params["center"] = center
  end

  local format = stdnse.get_script_args(SCRIPT_NAME .. ".format")
  if format then
    params["fmt"] = format
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

  local scale = stdnse.get_script_args(SCRIPT_NAME .. ".scale")
  if scale then
    params["scale"] = scale
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
